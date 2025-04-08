import os
import logging
import re
from typing import Dict, List
from flask import Flask, request, render_template, send_file, abort, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
import pandas as pd
from collections import defaultdict
import concurrent.futures
from core import NetworkTopology
from policy_engine import PolicyProcessor
from vendor_config import HuaweiConfigGenerator, H3CConfigGenerator, TopSecConfigGenerator, HillstoneConfigGenerator
import zipfile
import io

# 初始化 Flask 应用
app = Flask(__name__)
app.secret_key = os.urandom(24)
logger = logging.getLogger(__name__)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)


# 用户认证相关函数
def load_users() -> Dict[str, str]:
    """从 user.txt 加载用户信息，格式为 username:password"""
    users = {}
    default_users = {"admin": generate_password_hash("password123")}
    try:
        with open('user.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if ':' in line:
                    username, password = line.strip().split(':', 1)
                    users[username] = generate_password_hash(password)
    except FileNotFoundError:
        logger.warning("未找到 user.txt 文件，使用默认用户")
        return default_users
    except Exception as e:
        logger.error(f"加载用户文件失败: {e}")
        return default_users
    return users if users else default_users


VALID_USERS = load_users()


def verify_user(username: str, password: str) -> bool:
    """验证用户名和密码"""
    return username in VALID_USERS and check_password_hash(VALID_USERS[username], password)


# 策略处理函数
def process_single_policy(processor: PolicyProcessor, row, ticket_id: str, user_id: str) -> Dict[str, List]:
    """处理单个策略，多线程调用"""
    try:
        # 预处理非标准分隔符
        src_ip_str = re.sub(r'[;、\s]+', ',', str(row['src_ip']))
        dst_ip_str = re.sub(r'[;、\s]+', ',', str(row['dst_ip']))

        # 匹配 IP 地址或 IP 范围的正则表达式
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:-\d{1,3})?|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})'

        # 提取所有 IP 或 IP 范围
        src_ips = [ip.strip() for ip in re.findall(ip_pattern, src_ip_str) if ip.strip()]
        dst_ips = [ip.strip() for ip in re.findall(ip_pattern, dst_ip_str) if ip.strip()]

        # 处理端口
        port_str = re.sub(r'[;、\s]+', ',', str(row['port']) if pd.notna(row['port']) else '')
        port_pattern = r'(\d+(?:-\d+)?)'  # 匹配单端口或范围，如 "80" 或 "81-86"
        ports = [p.strip() for p in re.findall(port_pattern, port_str) if p.strip()]

        # 处理协议和动作
        proto = str(row['proto']) if pd.notna(row['proto']) else ''
        action = str(row['action']) if pd.notna(row['action']) else 'permit'

        # 日志记录清洗后的数据
        logger.info(
            f"用户 {user_id} 清洗后数据: src_ips={src_ips}, dst_ips={dst_ips}, ports={ports}, proto={proto}, action={action}")

        # 如果没有有效的 IP，记录警告并跳过
        if not src_ips:
            logger.warning(f"用户 {user_id} 策略 {row.name} 的 src_ip 未匹配到有效 IP: {src_ip_str}")
            return {}
        if not dst_ips:
            logger.warning(f"用户 {user_id} 策略 {row.name} 的 dst_ip 未匹配到有效 IP: {dst_ip_str}")
            return {}

        result = processor.process_policy(src_ips, dst_ips, proto, ports, action, ticket_id)
        if result.get("error"):
            logger.warning(f"用户 {user_id} 策略 {row.name} 处理失败: {result['error']}")
            return {}

        firewall_rules = defaultdict(list)
        for fw_name, fw_rules in result["firewall_rules"].items():
            for rule_key, rule_data in fw_rules.items():
                firewall_rules[fw_name].append({
                    'rule_key': rule_key,
                    'sources': rule_data['sources'],
                    'destinations': rule_data['destinations'],
                    'proto': rule_data['proto'],
                    'ports': rule_data['ports'],
                    'action': rule_data['action'],
                    'ticket_id': rule_data['ticket_id']
                })
        return firewall_rules
    except Exception as e:
        logger.error(f"用户 {user_id} 处理策略 {row.name} 时出错: {e}")
        return {}


# 路由定义
@app.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录页面"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if verify_user(username, password):
            session['user_id'] = username
            logger.info(f"用户 {username} 登录成功")
            return redirect(url_for('index'))
        logger.warning(f"用户 {username} 登录失败: 用户名或密码错误")
        return render_template('login.html', error="用户名或密码错误")
    return render_template('login.html', error=None)


@app.route('/logout')
def logout():
    """用户注销"""
    user_id = session.pop('user_id', None)
    if user_id:
        logger.info(f"用户 {user_id} 已注销")
    return redirect(url_for('login'))


@app.route('/', methods=['GET'])
def index():
    """主页：显示上传表单"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    return render_template('index.html', message=None, files=None, user_id=user_id)


@app.route('/generate', methods=['POST'])
def generate_config():
    """处理文件上传和配置生成"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    policies_file = request.files.get('policies_file')
    topology_file = request.files.get('topology_file')
    ticket_id = request.form.get('ticket_id')

    if not policies_file or not policies_file.filename:
        return render_template('index.html', message="请上传工单文件", files=None, user_id=user_id)
    if not ticket_id:
        return render_template('index.html', message="请输入工单号", files=None, user_id=user_id)

    topology_path = "topology_simple.json"
    if topology_file and topology_file.filename:
        topology_file.save(topology_path)
    elif not os.path.exists(topology_path):
        return render_template('index.html', message="未提供拓扑文件且默认文件不存在", files=None, user_id=user_id)

    try:
        logger.info(f"用户 {user_id} 开始处理工单，工单号: {ticket_id}")
        topology = NetworkTopology(topology_path)

        # 将文件流读取到 BytesIO 中，避免 seekable 问题
        file_content = policies_file.stream.read()
        excel_file = io.BytesIO(file_content)

        # 读取 Excel 文件，从第 4 行开始
        df = pd.read_excel(
            excel_file,
            header=None,
            skiprows=4,
            names=['seq', 'src_ip', 'dst_ip', 'port', 'proto', 'start_time', 'end_time', 'action', 'long_link'],
            usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8],
            engine='openpyxl'
        )
        # 移除包含 "策略规则说明" 的行及其之后的内容
        mask = df.apply(lambda row: row.astype(str).str.contains('策略规则说明：').any(), axis=1)
        if mask.any():
            df = df.loc[:mask.idxmax() - 1]
        df = df.dropna(how='all')  # 删除全为空的行

        # 处理策略
        processor = PolicyProcessor(topology)
        all_firewall_rules = defaultdict(list)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_to_row = {executor.submit(process_single_policy, processor, row, ticket_id, user_id): row.name for
                             _, row in df.iterrows()}
            for future in concurrent.futures.as_completed(future_to_row):
                idx = future_to_row[future]
                try:
                    firewall_rules = future.result()
                    for fw_name, rules in firewall_rules.items():
                        all_firewall_rules[fw_name].extend(rules)
                except Exception as e:
                    logger.error(f"用户 {user_id} 策略 {idx} 处理失败: {e}")

        # 生成配置
        user_output_dir = os.path.join("configs", user_id)
        os.makedirs(user_output_dir, exist_ok=True)
        success = True
        for fw_name, rules_list in all_firewall_rules.items():
            fw = topology.firewalls[fw_name]
            try:
                generators = {
                    "华为": HuaweiConfigGenerator,
                    "H3C": H3CConfigGenerator,
                    "天融信": TopSecConfigGenerator,
                    "山石": HillstoneConfigGenerator
                }
                if fw.type in generators:
                    generators[fw.type].generate(user_output_dir, fw_name, rules_list)
                else:
                    logger.error(f"用户 {user_id} 不支持的防火墙类型: {fw.type}")
                    success = False
            except Exception as e:
                logger.error(f"用户 {user_id} 生成 {fw_name} 配置失败: {e}")
                success = False

        message = f"配置生成{'成功' if success else '失败'}，用户 {user_id} 的文件位于 configs/{user_id}"
        return redirect(url_for('download_config', user_id=user_id, pattern='.*', message=message))

    except Exception as e:
        logger.error(f"用户 {user_id} 处理工单失败: {e}")
        return render_template('index.html', message=f"处理失败: {e}", files=None, user_id=user_id)


@app.route('/download-config/<user_id>/<pattern>', methods=['GET'])
def download_config(user_id: str, pattern: str):
    """根据正则表达式查询并展示匹配的配置文件"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    user_dir = os.path.join("configs", user_id)
    message = request.args.get('message', None)
    if not os.path.exists(user_dir):
        return render_template('index.html', message="用户配置目录未找到", files=None, user_id=user_id)

    try:
        regex = re.compile(pattern)
        matched_files = [f for f in os.listdir(user_dir) if
                         regex.match(f) and os.path.isfile(os.path.join(user_dir, f))]
        if not matched_files:
            return render_template('index.html', message=message or f"未找到匹配 '{pattern}' 的配置文件", files=None,
                                   user_id=user_id)

        files_info = [
            {"filename": f, "download_url": url_for('download_single_config_file', user_id=user_id, filename=f)} for f
            in matched_files]
        return render_template('index.html', message=message or f"找到 {len(matched_files)} 个匹配文件",
                               files=files_info, user_id=user_id)
    except re.error:
        return render_template('index.html', message="无效的正则表达式", files=None, user_id=user_id)


@app.route('/download-config-file/<user_id>/<filename>', methods=['GET'])
def download_single_config_file(user_id: str, filename: str):
    """下载单个配置文件"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    config_path = os.path.join("configs", user_id, filename)
    if not os.path.exists(config_path) or not os.path.isfile(config_path):
        abort(404, description="配置文件未找到")
    return send_file(config_path, as_attachment=True, download_name=filename)


@app.route('/download-config-zip/<user_id>/<pattern>', methods=['GET'])
def download_config_zip(user_id: str, pattern: str):
    """下载匹配的配置文件打包为 ZIP"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    user_dir = os.path.join("configs", user_id)
    if not os.path.exists(user_dir):
        abort(404, description="用户配置目录未找到")

    try:
        regex = re.compile(pattern)
        matched_files = [f for f in os.listdir(user_dir) if
                         regex.match(f) and os.path.isfile(os.path.join(user_dir, f))]
        if not matched_files:
            abort(404, description=f"未找到匹配 '{pattern}' 的配置文件")

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename in matched_files:
                zipf.write(os.path.join(user_dir, filename), filename)
        memory_file.seek(0)
        return send_file(memory_file, mimetype='application/zip', as_attachment=True,
                         download_name=f"{user_id}_configs.zip")
    except re.error:
        abort(400, description="无效的正则表达式")


@app.route('/delete-configs/<user_id>', methods=['POST'])
def delete_configs(user_id: str):
    """删除用户的所有配置文件并跳转回生成页面"""
    if 'user_id' not in session or session['user_id'] != user_id:
        return redirect(url_for('login'))

    user_dir = os.path.join("configs", user_id)
    if os.path.exists(user_dir):
        for filename in os.listdir(user_dir):
            file_path = os.path.join(user_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        logger.info(f"用户 {user_id} 的所有配置文件已删除")
        return redirect(url_for('index', message="所有配置文件已删除"))
    return redirect(url_for('index', message="用户配置目录未找到"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)