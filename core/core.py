import json
import ipaddress
from collections import defaultdict
import heapq
import logging
from typing import Dict, List, Tuple, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_ports(ports: List[str]) -> set:
    """解析端口，支持范围和单端口，处理英文和中文逗号"""
    result = set()
    for port_str in ports:
        port_segments = port_str.replace('，', ' ').replace(',', ' ').split()
        for segment in port_segments:
            if '-' in segment:
                start, end = map(int, segment.split('-'))
                if 1 <= start <= end <= 65535:
                    result.update(str(i) for i in range(start, end + 1))
                else:
                    logger.warning(f"端口范围 {segment} 超出有效范围（1-65535），忽略")
            else:
                if segment.isdigit() and 1 <= int(segment) <= 65535:
                    result.add(segment)
                else:
                    logger.warning(f"端口 {segment} 超出有效范围（1-65535）或无效，忽略")
    return result


class SecurityDomain:
    def __init__(self, name: str, ip_ranges: List[str], intra_connections: List[str] = None,
                 connected_firewalls: List[dict] = None):
        self.name = name
        self.ip_ranges = [ipaddress.IPv4Network(r) for r in ip_ranges]
        self.intra_connections = intra_connections or []
        self.connected_firewalls = connected_firewalls or []


class Firewall:
    def __init__(self, name: str, fw_type: str, domains: Dict[str, SecurityDomain]):
        self.name = name
        self.type = fw_type
        self.domains = domains


class NetworkTopology:
    def __init__(self, json_path: str):
        self.firewalls = {}
        self.graph = defaultdict(list)
        self.explicit_paths = {}
        self.global_acl = []  # 全局 ACL 列表
        self._load_topology(json_path)
        self._build_connection_graph()
        self._validate_topology()

    def _load_topology(self, json_path: str):
        encodings = ['utf-8-sig', 'gbk', 'utf-8']
        for encoding in encodings:
            try:
                with open(json_path, 'r', encoding=encoding) as f:
                    data = json.load(f)
                    logger.info(f"成功以 {encoding} 编码加载文件")
                    break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"文件加载失败: {str(e)}")
                raise
        else:
            raise ValueError(f"无法解码文件，支持的编码: {encodings}")

        if 'firewalls' not in data or not isinstance(data['firewalls'], list):
            raise ValueError("拓扑文件格式错误")

        # 加载全局 ACL
        self.global_acl = data.get('global_acl', [])
        for path in data.get('explicit_paths', []):
            start = (path['start']['firewall'], path['start']['domain'])
            end = (path['end']['firewall'], path['end']['domain'])
            self.explicit_paths[(start, end)] = path['path']

        for fw_data in data['firewalls']:
            domains = {}
            for sd in fw_data.get('security_domains', []):
                domain = SecurityDomain(
                    name=sd['name'],
                    ip_ranges=sd.get('ip_ranges', []),
                    intra_connections=sd.get('intra_connections', []),
                    connected_firewalls=sd.get('connected_firewalls', [])
                )
                domains[domain.name] = domain
            fw = Firewall(name=fw_data['name'], fw_type=fw_data['type'], domains=domains)
            self.firewalls[fw.name] = fw

    def _build_connection_graph(self):
        for fw in self.firewalls.values():
            domains = list(fw.domains.keys())
            for i, src_domain in enumerate(domains):
                for dst_domain in domains[i + 1:]:
                    src_node = (fw.name, src_domain)
                    dst_node = (fw.name, dst_domain)
                    self.graph[src_node].append(dst_node)
                    self.graph[dst_node].append(src_node)
                domain_obj = fw.domains[src_domain]
                for conn in domain_obj.connected_firewalls:
                    target_fw = conn["firewall"]
                    via_domain = conn["via_domain"]
                    src = (fw.name, src_domain)
                    dst = (target_fw, via_domain)
                    self.graph[src].append(dst)
                    self.graph[dst].append(src)

    def _validate_topology(self):
        if not self.firewalls:
            raise ValueError("拓扑文件中未定义任何防火墙")
        for fw_name, fw in self.firewalls.items():
            if not fw.domains:
                raise ValueError(f"防火墙 {fw_name} 未配置安全域")

    def get_interfaces(self, fw_name: str, domain: str) -> List[str]:
        return [
            conn["via_domain"]
            for conn in self.firewalls[fw_name].domains[domain].connected_firewalls
        ]

    def find_shortest_path(self, start: Tuple[str, str], end: Tuple[str, str]) -> List[Tuple[str, str]]:
        if (start, end) in self.explicit_paths:
            return self.explicit_paths[(start, end)]

        heap = []
        heapq.heappush(heap, (0, start, []))
        visited = set()
        path_weights = defaultdict(lambda: float('inf'))
        while heap:
            current_cost, current_node, path = heapq.heappop(heap)
            if current_node in visited:
                continue
            visited.add(current_node)
            new_path = path + [current_node]
            if current_node == end:
                return new_path
            for neighbor in self.graph.get(current_node, []):
                edge_cost = 1 if current_node[0] == neighbor[0] else 5
                total_cost = current_cost + edge_cost
                if total_cost < path_weights[neighbor]:
                    path_weights[neighbor] = total_cost
                    heapq.heappush(heap, (total_cost, neighbor, new_path))
        return []

    def _handle_ip_range(self, ip_range: str) -> Tuple[str, str]:
        """处理范围 IP，确保整个范围属于同一安全域，支持 10.16.152.91-10.16.152.92 和 10.16.152.91-92"""
        try:
            # 处理完整范围格式，如 "10.16.152.91-10.16.152.92"
            if '-' in ip_range and ip_range.count('.') == 6:
                start_ip, end_ip = ip_range.split('-')
                base_part_start = start_ip.rsplit('.', 1)[0]
                base_part_end = end_ip.rsplit('.', 1)[0]
                if base_part_start != base_part_end:
                    logger.error(f"IP范围 {ip_range} 前缀不一致: {base_part_start} != {base_part_end}")
                    return None
                start = int(start_ip.split('.')[-1])
                end = int(end_ip.split('.')[-1])
                base_part = base_part_start  # 统一赋值 base_part
            # 处理简写范围格式，如 "10.16.152.91-92"
            elif '-' in ip_range and not ip_range.startswith('range'):
                base_part = ip_range.rsplit('.', 1)[0]
                range_part = ip_range.split('.')[-1]
                start, end = map(int, range_part.split('-'))
            else:
                raise ValueError(f"无效IP范围格式: {ip_range}")

            if not (0 <= start <= end <= 255):
                raise ValueError(f"无效IP范围: {ip_range}")

            start_ip = f"{base_part}.{start}"
            end_ip = f"{base_part}.{end}"
            start_owner = self._get_single_ip_owner(start_ip)
            end_owner = self._get_single_ip_owner(end_ip)

            if not start_owner or start_owner != end_owner:
                logger.error(f"IP范围 {ip_range} 跨越不同安全域或无归属: {start_owner} != {end_owner}")
                return None

            # 检查范围内的所有 IP 是否属于同一安全域
            for i in range(start, end + 1):
                ip = f"{base_part}.{i}"
                if self._get_single_ip_owner(ip) != start_owner:
                    logger.error(f"IP范围 {ip_range} 中 {ip} 归属不一致")
                    return None

            return start_owner
        except ValueError as e:
            logger.error(f"IP范围解析失败: {str(e)}")
            return None

    def find_ip_owner(self, ip_str: str) -> Optional[Tuple[str, str]]:
        """优化查找 IP 归属，确保选择最精确的子网"""
        try:
            # 支持完整范围格式，如 "10.16.152.91-10.16.152.92"
            if '-' in ip_str and ip_str.count('.') == 6:
                return self._handle_ip_range(ip_str)
            # 支持简写范围格式，如 "10.16.152.91-92"
            elif '-' in ip_str and not ip_str.startswith('range'):
                return self._handle_ip_range(ip_str)
            elif '/' in ip_str:
                network = ipaddress.IPv4Network(ip_str, strict=False)
                candidates = []
                for fw in self.firewalls.values():
                    for domain in fw.domains.values():
                        for net in domain.ip_ranges:
                            if network.subnet_of(net):
                                candidates.append((net.prefixlen, fw.name, domain.name))
                if candidates:
                    candidates.sort(reverse=True)  # 按前缀长度降序，选择最精确的子网
                    return candidates[0][1], candidates[0][2]
                return None
            ip = ipaddress.IPv4Address(ip_str)
            candidates = []
            for fw in self.firewalls.values():
                for domain in fw.domains.values():
                    for net in domain.ip_ranges:
                        if ip in net:
                            candidates.append((net.prefixlen, fw.name, domain.name))
            if candidates:
                candidates.sort(reverse=True)  # 按前缀长度降序，选择最精确的子网
                return candidates[0][1], candidates[0][2]
            return None
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
            logger.error(f"IP格式解析失败: {ip_str} - {str(e)}")
            return None

    def _get_single_ip_owner(self, ip_str: str) -> Optional[Tuple[str, str]]:
        """查找单个 IP 的归属"""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            candidates = []
            for fw in self.firewalls.values():
                for domain in fw.domains.values():
                    for net in domain.ip_ranges:
                        if ip in net:
                            candidates.append((net.prefixlen, fw.name, domain.name))
            if candidates:
                candidates.sort(reverse=True)  # 按前缀长度降序，选择最精确的子网
                return candidates[0][1], candidates[0][2]
            return None
        except ipaddress.AddressValueError:
            return None

    def check_global_acl(self, src_fw: str, src_zone: str, dst_fw: str, dst_zone: str) -> bool:
        """检查全局 ACL 是否允许源防火墙和安全域到目标防火墙和安全域的访问"""
        for acl in self.global_acl:
            if (acl.get('source_fw') == src_fw and
                    acl.get('source_zone') == src_zone and
                    acl.get('destination_fw') == dst_fw and
                    acl.get('destination_zone') == dst_zone):
                action = acl.get('action', 'permit')
                if action.lower() == 'deny':
                    logger.info(f"全局 ACL 禁止 {src_fw}.{src_zone} 到 {dst_fw}.{dst_zone} 的访问")
                    return False
                return True
        logger.debug(f"未找到 {src_fw}.{src_zone} 到 {dst_fw}.{dst_zone} 的全局 ACL 规则，默认允许")
        return True
