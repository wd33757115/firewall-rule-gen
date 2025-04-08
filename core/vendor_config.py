import logging
import os
from typing import List

logger = logging.getLogger(__name__)


class HuaweiConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str, is_source: bool = True) -> List[str]:
        """格式化华为 USG6000F 系列的源/目的地址"""
        # logger.info(f"处理地址: {ip_str}, is_source={is_source}")
        prefix = "source-address" if is_source else "destination-address"
        # 处理完整范围格式，如 "10.16.152.91-10.16.152.92"
        if '-' in ip_str and ip_str.count('.') == 6:
            start_ip, end_ip = ip_str.split('-')
            return [f"{prefix} range {start_ip} {end_ip}"]
        # 处理简写范围格式，如 "10.16.152.91-92"
        elif '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            start_end = ip_str.split('.')[-1].split('-')
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            return [f"{prefix} range {start} {end}"]
        elif '/' in ip_str:
            ip, prefix_len = ip_str.split('/')
            return [f"{prefix} {ip} {prefix_len}"]
        return [f"{prefix} {ip_str} 32"]

    @staticmethod
    def _format_ports(ports: set[str], proto: str) -> str:
        """格式化华为 USG6000F 系列的服务端口，支持范围和单端口混合"""
        if not ports:
            return f"service {proto}" if proto else "service any"

        # 将端口按数值排序并分组处理
        port_list = sorted(ports, key=lambda x: int(x.split('-')[0]) if '-' in x else int(x))
        formatted = []
        i = 0
        while i < len(port_list):
            if '-' in port_list[i]:
                # 直接添加范围端口
                start, end = port_list[i].split('-')
                formatted.append(f" {start} to  {end}")
                i += 1
            else:
                # 检查连续端口
                start = int(port_list[i])
                j = i + 1
                while j < len(port_list) and '-' not in port_list[j] and int(port_list[j]) == start + (j - i):
                    j += 1
                if j - i > 2:  # 如果连续端口超过2个，使用 range
                    end = int(port_list[j - 1])
                    formatted.append(f" {start} to  {end}")
                    i = j
                else:  # 单端口或少量非连续端口，单独列出
                    formatted.append(str(start))
                    i += 1

        ports_str = ' '.join(formatted)
        return f"service protocol {proto} destination-port {ports_str}"

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成华为 USG6000F 系列防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"rule name {ticket_id}-{rule_index}",
            f"description {ticket_id}",
            f"source-zone {src_zone}",
            f"destination-zone {dst_zone}"
        ]

        # 配置源地址
        for src in rule_data.get("sources", []):
            config.extend(HuaweiConfigGenerator._format_address(src, is_source=True))

        # 配置目的地址
        for dst in rule_data.get("destinations", []):
            config.extend(HuaweiConfigGenerator._format_address(dst, is_source=False))

        # 配置服务和端口
        proto = rule_data.get("proto", "")
        ports = rule_data.get("ports", set())
        config.append(HuaweiConfigGenerator._format_ports(ports, proto))

        # 配置动作
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"action {action}")

        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成华为 USG6000F 系列防火墙的配置"""
        config = [
            "system-view",
            "security-policy",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(HuaweiConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")  # 规则间换行
            rule_index += 1
        config.append("quit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成华为防火墙配置: {output_path}")


class H3CConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str, is_source: bool = True) -> List[str]:
        """格式化 H3C F50X0 系列的源/目的地址"""
        prefix = "source" if is_source else "destination"
        if not ip_str or ip_str.strip() == "":
            logger.warning(f"无效的IP地址: {ip_str}，跳过处理")
            return [f"{prefix}-ip-host 0.0.0.0"]

        # 处理完整范围格式，如 "10.16.152.91-10.16.152.92"
        if '-' in ip_str and ip_str.count('.') == 6:
            start, end = ip_str.split('-')
            return [f"{prefix}-ip-range {start} {end}"]
        # 处理简写范围格式，如 "10.253.22.24-28"
        elif '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            range_part = ip_str.split('.')[-1]
            start_end = range_part.split('-')
            if len(start_end) != 2:
                logger.error(f"IP范围格式错误: {ip_str}，预期为 'x.x.x.start-end'")
                return [f"{prefix}-ip-host {base_ip}.{start_end[0]}"]
            start = f"{base_ip}.{start_end[0]}"
            end = f"{base_ip}.{start_end[1]}"
            return [f"{prefix}-ip-range {start} {end}"]
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            return [f"{prefix}-ip-subnet {ip} {mask}"]
        return [f"{prefix}-ip-host {ip_str}"]

    @staticmethod
    def _format_ports(ports: set, proto: str) -> List[str]:
        """格式化 H3C F50X0 系列的服务端口"""
        if not ports:
            return []
        formatted = []
        for p in sorted(ports):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"service-port {proto} destination range {start} {end}")
            else:
                formatted.append(f"service-port {proto} destination eq {p}")
        return formatted

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成 H3C F50X0 系列防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"security-policy ip",
            f"rule {rule_index} name {ticket_id}-{rule_index}",
            f" description {ticket_id}",
            f" source-zone {src_zone}",
            f" destination-zone {dst_zone}"
        ]

        # 配置源地址
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in H3CConfigGenerator._format_address(src, is_source=True)])

        # 配置目的地址
        for dst in rule_data.get("destinations", []):
            config.extend([f"  {line}" for line in H3CConfigGenerator._format_address(dst, is_source=False)])

        # 配置服务和端口
        proto = rule_data['proto'] if rule_data['proto'] else 'ip'
        if ports := rule_data.get("ports"):
            config.extend(H3CConfigGenerator._format_ports(ports, proto))
        else:
            config.append(f" service {proto}")

        # 配置动作
        action = "pass" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f" action {action}")

        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成 H3C F50X0 系列防火墙的配置"""
        config = [
            "system-view",
        ]
        rule_index = 1
        for rule_data in rules:
            config.extend(H3CConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("return")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.txt")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成H3C防火墙配置: {output_path}")


class TopSecConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str) -> List[str]:
        """格式化天融信防火墙的源/目的地址"""
        if not ip_str or ip_str.strip() == "":
            logger.warning(f"无效的IP地址: {ip_str}，跳过处理")
            return ["source-address 0.0.0.0 255.255.255.255"]

        # 处理完整范围格式，如 "10.16.152.91-10.16.152.92"
        if '-' in ip_str and ip_str.count('.') == 6:
            start_ip, end_ip = ip_str.split('-')
            # 天融信不支持直接范围，转换为连续单 IP
            start = int(start_ip.split('.')[-1])
            end = int(end_ip.split('.')[-1])
            base_ip = start_ip.rsplit('.', 1)[0]
            return [f"source-address {base_ip}.{i} 255.255.255.255" for i in range(start, end + 1)]

        # 处理简写范围格式，如 "10.253.22.24-28"
        elif '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            range_part = ip_str.split('.')[-1]
            start, end = map(int, range_part.split('-'))
            return [f"source-address {base_ip}.{i} 255.255.255.255" for i in range(start, end + 1)]

        # 处理子网格式，如 "10.246.240.0/20"
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            mask_int = int(mask)
            subnet_mask = '.'.join([str((0xFFFFFFFF << (32 - mask_int)) >> (24 - 8 * i) & 0xFF) for i in range(4)])
            return [f"source-address {ip} {subnet_mask}"]

        # 处理单 IP
        return [f"source-address {ip_str} 255.255.255.255"]

    @staticmethod
    def _format_ports(ports: set) -> str:
        """格式化天融信防火墙的服务端口"""
        if not ports:
            return ""
        formatted = []
        for p in sorted(ports, key=lambda x: int(x.split('-')[0]) if '-' in x else int(x)):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"{start}-{end}")
            else:
                formatted.append(p)
        return ' '.join(formatted)

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成天融信防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"security-policy",
            f" rule {rule_index} name {ticket_id}-{rule_index}",
            f"  description {ticket_id}",
            f"  source-zone {src_zone}",
            f"  destination-zone {dst_zone}"
        ]
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in TopSecConfigGenerator._format_address(src)])
        for dst in rule_data.get("destinations", []):
            config.extend(
                [f"  {line.replace('source', 'destination')}" for line in TopSecConfigGenerator._format_address(dst)])
        if ports := rule_data.get("ports"):
            ports_str = TopSecConfigGenerator._format_ports(ports)
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto} port {ports_str}")
        else:
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto}")
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"  action {action}")
        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成天融信防火墙的配置"""
        config = ["configure"]
        rule_index = 1
        for rule_data in rules:
            config.extend(TopSecConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("exit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.cfg")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成天融信防火墙配置: {output_path}")


class HillstoneConfigGenerator:
    @staticmethod
    def _format_address(ip_str: str) -> List[str]:
        """格式化山石防火墙的源/目的地址"""
        if not ip_str or ip_str.strip() == "":
            logger.warning(f"无效的IP地址: {ip_str}，跳过处理")
            return ["address 0.0.0.0 mask 255.255.255.255"]

        # 处理完整范围格式，如 "10.16.152.91-10.16.152.92"
        if '-' in ip_str and ip_str.count('.') == 6:
            start_ip, end_ip = ip_str.split('-')
            start = int(start_ip.split('.')[-1])
            end = int(end_ip.split('.')[-1])
            base_ip = start_ip.rsplit('.', 1)[0]
            return [f"address {base_ip}.{i} mask 255.255.255.255" for i in range(start, end + 1)]

        # 处理简写范围格式，如 "10.253.22.24-28"
        elif '-' in ip_str and not ip_str.startswith('range'):
            base_ip = ip_str.rsplit('.', 1)[0]
            range_part = ip_str.split('.')[-1]
            start, end = map(int, range_part.split('-'))
            return [f"address {base_ip}.{i} mask 255.255.255.255" for i in range(start, end + 1)]

        # 处理子网格式，如 "10.246.240.0/20"
        elif '/' in ip_str:
            ip, mask = ip_str.split('/')
            mask_int = int(mask)
            subnet_mask = '.'.join([str((0xFFFFFFFF << (32 - mask_int)) >> (24 - 8 * i) & 0xFF) for i in range(4)])
            return [f"address {ip} mask {subnet_mask}"]

        # 处理单 IP
        return [f"address {ip_str} mask 255.255.255.255"]

    @staticmethod
    def _format_ports(ports: set) -> str:
        """格式化山石防火墙的服务端口"""
        if not ports:
            return ""
        formatted = []
        for p in sorted(ports, key=lambda x: int(x.split('-')[0]) if '-' in x else int(x)):
            if '-' in p:
                start, end = p.split('-')
                formatted.append(f"{start}-{end}")
            else:
                formatted.append(p)
        return ' '.join(formatted)

    @staticmethod
    def _generate_rule(rule_data: dict, rule_index: int) -> List[str]:
        """生成山石防火墙的安全策略规则"""
        src_zone, dst_zone = rule_data['rule_key']
        ticket_id = rule_data['ticket_id']
        config = [
            f"policy security",
            f" rule {rule_index} name {ticket_id}-{rule_index}",
            f"  source zone {src_zone}",
            f"  destination zone {dst_zone}"
        ]
        for src in rule_data.get("sources", []):
            config.extend([f"  {line}" for line in HillstoneConfigGenerator._format_address(src)])
        for dst in rule_data.get("destinations", []):
            config.extend([f"  {line.replace('source', 'destination')}" for line in
                           HillstoneConfigGenerator._format_address(dst)])
        if ports := rule_data.get("ports"):
            ports_str = HillstoneConfigGenerator._format_ports(ports)
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto} {ports_str}")
        else:
            proto = rule_data['proto'] if rule_data['proto'] else 'ip'
            config.append(f"  service {proto}")
        action = "permit" if rule_data.get("action", "").lower() == "permit" else "deny"
        config.append(f"  action {action}")
        return config

    @staticmethod
    def generate(output_dir: str, fw_name: str, rules: List[dict]):
        """生成山石防火墙的配置"""
        config = ["configure"]
        rule_index = 1
        for rule_data in rules:
            config.extend(HillstoneConfigGenerator._generate_rule(rule_data, rule_index))
            config.append("")
            rule_index += 1
        config.append("exit")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{fw_name}.cfg")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join([line for line in config if line.strip()]))
        logger.info(f"生成山石防火墙配置: {output_path}")
