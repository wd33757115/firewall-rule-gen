import logging
from collections import defaultdict
from typing import List, Dict, Tuple

from core import NetworkTopology, parse_ports

logger = logging.getLogger(__name__)

class PolicyProcessor:
    def __init__(self, topology: NetworkTopology):
        self.topology = topology

    def process_policy(self, src_ips: List[str], dst_ips: List[str], proto: str, ports: List[str], action: str,
                       ticket_id: str) -> Dict:
        """支持多端口和范围处理，检查全局 ACL，并记录src_ip到dst_ip的完整路径"""
        proto = proto if proto and str(proto).lower() != 'nan' else ''
        port_list = ports if ports and str(ports).lower() != 'nan' else []
        filtered_ports = parse_ports(port_list) if port_list else set()

        src_domains = self._get_unique_domains(src_ips)
        dst_domains = self._get_unique_domains(dst_ips)

        path_matrix = defaultdict(lambda: defaultdict(lambda: {
            'sources': set(),
            'destinations': set(),
            'proto': proto,
            'ports': filtered_ports,
            'action': action,
            'ticket_id': ticket_id
        }))

        for (src_fw, src_zone), src_group in src_domains.items():
            for (dst_fw, dst_zone), dst_group in dst_domains.items():
                # 计算路径
                path = self.topology.find_shortest_path((src_fw, src_zone), (dst_fw, dst_zone))
                if not path:
                    logger.debug(f"未找到从 {src_fw}.{src_zone} 到 {dst_fw}.{dst_zone} 的路径，跳过")
                    continue

                # 检查路径上每一对相邻节点是否符合全局 ACL
                for i in range(len(path) - 1):
                    current_fw, current_zone = path[i]
                    next_fw, next_zone = path[i + 1]
                    if not self.topology.check_global_acl(current_fw, current_zone, next_fw, next_zone):
                        logger.info(
                            f"路径 {current_fw}.{current_zone} -> {next_fw}.{next_zone} 被全局 ACL 禁止，跳过整个路径")
                        break
                else:  # 如果路径上所有段都通过 ACL 检查
                    # 日志记录完整路径
                    path_str = " -> ".join([f"{fw}.{domain}" for fw, domain in path])
                    for src_ip in src_group:
                        for dst_ip in dst_group:
                            logger.info(f"{src_ip} -> {dst_ip} 的完整路径: {path_str}")

                    # 生成防火墙规则
                    for i in range(len(path) - 1):
                        current = path[i]
                        next_node = path[i + 1]
                        if current[0] != next_node[0]:  # 跨防火墙跳过
                            continue

                        fw_name = current[0]
                        rule_key = (current[1], next_node[1])

                        path_matrix[fw_name][rule_key]['sources'].update(src_group)
                        path_matrix[fw_name][rule_key]['destinations'].update(dst_group)
                        path_matrix[fw_name][rule_key].update({
                            'proto': proto,
                            'ports': filtered_ports,
                            'action': action,
                            'ticket_id': ticket_id
                        })

        return {
            "firewall_rules": path_matrix,
            "error": None
        }
    #映射ip和安全域
    def _get_unique_domains(self, ips: List[str]) -> Dict[Tuple[str, str], set]:
        domain_map = defaultdict(set)
        for ip in ips:
            owner = self.topology.find_ip_owner(ip)
            if owner:
                domain_map[(owner[0], owner[1])].add(ip)
        return domain_map