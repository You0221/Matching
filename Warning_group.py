from typing import Dict, List
import os

class WarningGrouper:

    @staticmethod
    def extract_relative_path(full_path: str) -> str:
        """从完整路径中提取相对路径"""
        version_patterns = [
            "ansible-2.19.0b1",
            "ansible-2.20.0rc2",
            "ansible-2.19.0",
            "ansible-2.18.1",
            "ansible-2.17.4rc1",
            "ansible-2.17.1rc1",
        ]

        for pattern in version_patterns:
            if pattern in full_path:
                idx = full_path.index(pattern) + len(pattern)
                relative_path = full_path[idx:].lstrip('\\/')
                return relative_path

        return os.path.basename(full_path)

    @staticmethod
    def is_same_file(path1: str, path2: str) -> bool:
        """判断是否为相同文件"""
        rel1 = WarningGrouper.extract_relative_path(path1)
        rel2 = WarningGrouper.extract_relative_path(path2)

        if rel1 == rel2:
            return True

        norm1 = rel1.replace('\\', '/').lower()
        norm2 = rel2.replace('\\', '/').lower()

        return norm1 == norm2

    @staticmethod
    def group_warnings(parent_warnings: List[Dict], child_warnings: List[Dict]) -> Dict[str, Dict[str, List[Dict]]]:
        """
        按照文件路径将警告分组
        """
        file_groups = {}

        # 创建父警告文件组
        for pa in parent_warnings:
            file_key = WarningGrouper.extract_relative_path(pa['filename'])

            # 检查是否已经存在相同文件的组
            existing_group_key = None
            for existing_key in file_groups.keys():
                if WarningGrouper.is_same_file(file_key, existing_key):
                    existing_group_key = existing_key
                    break

            if existing_group_key is not None:
                # 添加到已有的文件组
                file_groups[existing_group_key]['parent'].append(pa)
            else:
                # 创建新组
                file_groups[file_key] = {'parent': [], 'child': []}
                file_groups[file_key]['parent'].append(pa)

        # 为子版本警告添加到相同文件组
        for ca in child_warnings:
            child_file_key = WarningGrouper.extract_relative_path(ca['filename'])

            # 寻找匹配的父版本文件组
            matching_group_key = None
            for parent_group_key in file_groups.keys():
                if WarningGrouper.is_same_file(child_file_key, parent_group_key):
                    matching_group_key = parent_group_key
                    break

            if matching_group_key is not None:
                file_groups[matching_group_key]['child'].append(ca)

        return file_groups


