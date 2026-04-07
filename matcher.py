import json
import os
from typing import List, Dict, Tuple, Optional
from 匹配算法 import Matcher
import re
from diff_generator import DiffGenerator
import glob
import warnings
from fix_analyzer import ASTFixAnalyzer, FixStatus
try:
    from packaging import version as pkg_version
    HAS_PACKAGING = True
except ImportError:
    HAS_PACKAGING = False
    warnings.warn("packaging 模块未安装，版本排序将使用字符串排序，可能不准确")

class FixMatcher(Matcher):

    def __init__(self, matching_threshold: int = 3, context_lines: int = 3,
                 snippet_similarity: float = 0.9, hash_size: int = 20,
                 cwe_mapping_dir: Optional[str] = None):
        super().__init__(matching_threshold, context_lines, snippet_similarity, hash_size, cwe_mapping_dir)
        self.fix_analyzer = ASTFixAnalyzer()
        self.version_index_map = {}  # version_name -> index (1-based)

    def analyze_fix_status(self, parent_warning: Dict,
                           parent_source_dir: str, child_source_dir: str,
                           parent_version_name: str, child_version_name: str,
                           diff_content: Optional[str] = None) -> Tuple[FixStatus, str, Optional[str]]:
        """
        分析警告的修复状态
        """
        # 获取相对路径
        relative_path = self.extract_relative_path(parent_warning['filename'])

        # 构建文件路径
        parent_file_path = os.path.join(parent_source_dir, relative_path)
        child_file_path = os.path.join(child_source_dir, relative_path)

        # 检查文件是否存在
        if not os.path.exists(parent_file_path):
            return FixStatus.UNKNOWN, f"父文件不存在: {parent_file_path}", None

        if not os.path.exists(child_file_path):
            # 如果子文件不存在，则整个文件被删除，无法得知是否修改
            return FixStatus.UNKNOWN, "文件被删除", None

        try:
            old_idx = self.version_index_map.get(parent_version_name)
            new_idx = self.version_index_map.get(child_version_name)
            diff_changes = self.fix_analyzer.analyze_diff_changes(
                parent_file_path, child_file_path,
                old_version_index=old_idx,
                new_version_index=new_idx,
                diff_content=diff_content
            )
            status, reason = self.fix_analyzer.classify_removed_warning(
                parent_warning, parent_file_path, child_file_path, diff_changes
            )
            return status, reason, child_file_path
        except Exception as e:
            print(f"分析修复状态时出错: {e}")
            return FixStatus.UNKNOWN, f"分析出错: {str(e)}", child_file_path

    def match_warnings_between_versions_with_fix_analysis(
            self, parent_warnings: List[Dict], child_warnings: List[Dict],
            parent_source_dir: str, child_source_dir: str,
            parent_version_name: str, child_version_name: str
    ) -> Dict[str, List[Dict]]:
        match_result = super().match_warnings_between_versions(
            parent_warnings, child_warnings, parent_source_dir, child_source_dir
        )
        # 添加版本信息
        match_result['parent_version'] = parent_version_name
        match_result['child_version'] = child_version_name
        # 清空原有分类
        match_result['fixed_warnings'] = []
        match_result['non_fix_warnings'] = []
        match_result['unknown_status_warnings'] = []
        match_result['fix_statistics'] = {'fixed': 0, 'non_fix': 0, 'unknown': 0}
        return match_result

    def run_matching(self, version_files: List[str],
                     source_base_dir: str, output_dir: str,
                     commit_list: Optional[List[str]] = None):
        """
        运行带有修复分析的匹配算法
        """
        diff_generator = DiffGenerator(output_dir)
        # 加载版本数据
        versions = []
        for i, file_path in enumerate(version_files):
            warnings = self.load_warnings(file_path)
            basename = os.path.basename(file_path)
            # 去掉工具前缀
            for tool in ['bandit', 'codeql', 'horusec', 'pylint', 'semgrep']:
                if basename.startswith(tool + '_'):
                    basename = basename[len(tool) + 1:]
                    break
            version_name = basename.replace('.json', '')
            source_dir = os.path.join(source_base_dir, version_name)
            commit_id = commit_list[i] if commit_list and i < len(commit_list) else None
            versions.append({
                'name': version_name,
                'file': file_path,
                'warnings': warnings,
                'count': len(warnings),
                'source_dir': source_dir,
                'commit_id': commit_id  # 新增
            })

        for idx, version in enumerate(versions, start=1):
            self.version_index_map[version['name']] = idx

        warnings_tracking = {}
        global_match_stats = {
            'exact': 0,
            'location': 0,
            'snippet': 0,
            'location_and_snippet': 0,
            'hash': 0
        }

        global_fix_stats = {
            'fixed': 0,
            'non_fix': 0,
            'unknown': 0
        }

        print("\n开始版本间匹配与修复分析...")

        # 初始化警告跟踪
        for i, version in enumerate(versions):
            for warning in version['warnings']:
                warning_id = warning['unique_id']
                if warning_id not in warnings_tracking:
                    warnings_tracking[warning_id] = {
                        'warning': warning,
                        'origin_version': version['name'],
                        'appearance_history': [version['name']],  # 记录出现在哪些版本
                        'disappeared_version': None,  # 在哪一版本消失
                        'fix_status': None,
                        'fix_reason': '',
                        'match_history': [],
                        'fix_version': None
                    }

        # 主匹配循环
        for i in range(len(versions) - 1):
            version_key = versions[i]['name']
            parent_warnings = versions[i]['warnings']
            parent_source_dir = versions[i]['source_dir']

            print(f"\n匹配 {version_key} (包含 {len(parent_warnings)} 个警告) 与后续版本:")
            # warning_disappeared = {warning['unique_id']: False for warning in parent_warnings}
            #对于每个父版本警告，跟踪它是否已经在某个版本中消失了
            warning_disappeared = {}
            for warning in parent_warnings:
                warning_id = warning['unique_id']
                # 如果已经消失了，就不再参与匹配
                if warnings_tracking[warning_id]['disappeared_version'] is not None:
                    warning_disappeared[warning_id] = True
                else:
                    warning_disappeared[warning_id] = False

            for j in range(i + 1, len(versions)):
                child_version_name = versions[j]['name']
                child_warnings = versions[j]['warnings']
                child_source_dir = versions[j]['source_dir']

                # 只选择还未消失的警告进行匹配
                active_parent_warnings = []
                for warning in parent_warnings:
                    warning_id = warning['unique_id']
                    if not warning_disappeared[warning_id]:
                        active_parent_warnings.append(warning)

                if not active_parent_warnings:
                    print(f"  {child_version_name}: 没有活跃警告需要匹配")
                    continue

                print(f"  与 {child_version_name} 匹配并分析修复状态...")

                # 使用匹配方法
                match_result = self.match_warnings_between_versions_with_fix_analysis(
                    active_parent_warnings,
                    child_warnings,
                    parent_source_dir,
                    child_source_dir,
                    version_key,
                    child_version_name
                )

                # 更新匹配统计
                for match_type, count in match_result.get('match_stats', {}).items():
                    if match_type in global_match_stats:
                        global_match_stats[match_type] += count

                # 更新修复统计
                # for fix_type, count in match_result.get('fix_statistics', {}).items():
                #     if fix_type in global_fix_stats:
                #         global_fix_stats[fix_type] += count

                # 处理 false_positives
                for false_positive in match_result['false_positives']:
                    parent_warning = false_positive['parent_warning']
                    child_warning = false_positive['child_warning']
                    parent_id = parent_warning['unique_id']
                    child_id = child_warning['unique_id']

                    # 记录父警告出现在这个版本
                    if child_version_name not in warnings_tracking[parent_id]['appearance_history']:
                        warnings_tracking[parent_id]['appearance_history'].append(child_version_name)

                    # 记录匹配历史（父警告侧）
                    warnings_tracking[parent_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': false_positive['match_type'],
                        'status': 'false_positive',
                        'matched_child_warning': child_warning
                    })

                    if child_id in warnings_tracking:
                        # 子警告可能已经有 origin_version，现在需要覆盖为父警告的 origin_version
                        warnings_tracking[child_id]['origin_version'] = warnings_tracking[parent_id]['origin_version']


                # 处理消失的警告（true_positives）
                for parent_warning in match_result.get('true_positives', []):
                    warning_id = parent_warning['unique_id']
                    if warnings_tracking[warning_id]['disappeared_version'] is not None:
                        continue

                    # 生成 diff 片段
                    relative_path = self.extract_relative_path(parent_warning['filename'])
                    diff_file = diff_generator.generate_diff(
                        relative_path,
                        parent_warning['line_number'],
                        warning_id,
                        versions[i]['source_dir'],
                        versions[j]['source_dir'],
                        versions[i]['name'],
                        versions[j]['name'],
                        old_version_index=i + 1,
                        new_version_index=j + 1,
                        warning_dict=parent_warning
                    )

                    # 读取 diff 内容
                    diff_content = None
                    if diff_file:
                        try:
                            with open(diff_file, 'r', encoding='utf-8') as f:
                                diff_content = f.read()
                        except Exception:
                            pass

                    # 调用修复分析，传入 diff 内容
                    status, reason, child_file_path = self.analyze_fix_status(
                        parent_warning, parent_source_dir, child_source_dir,
                        version_key, child_version_name,
                        diff_content=diff_content
                    )

                    # 记录消失版本
                    warnings_tracking[warning_id]['disappeared_version'] = child_version_name
                    warnings_tracking[warning_id]['true_positive_version'] = child_version_name
                    warnings_tracking[warning_id]['fix_status'] = status.value
                    warnings_tracking[warning_id]['fix_reason'] = reason
                    warning_disappeared[warning_id] = True

                    if diff_file:
                        warnings_tracking[warning_id]['diff_file'] = diff_file

                    warnings_tracking[warning_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': 'none',
                        'status': status.value,
                        'matched_child_warning': None,
                        'fix_reason': reason
                    })

                    if status == FixStatus.FIXED:
                        global_fix_stats['fixed'] += 1
                    elif status == FixStatus.NON_FIX:
                        global_fix_stats['non_fix'] += 1
                    else:
                        global_fix_stats['unknown'] += 1

        for warning_id, tracking in warnings_tracking.items():
            if tracking.get('disappeared_version') is not None:
                tracking['status'] = 'true_positive'
            else:
                tracking['status'] = 'false_positive'
            tracking['true_positive_version'] = tracking.get('disappeared_version')

        # 生成最终结果
        final_results = self.generate_results(warnings_tracking, versions)
        final_results['global_match_statistics'] = global_match_stats
        final_results['global_fix_statistics'] = global_fix_stats

        # 保存结果
        self.save_results(final_results, output_dir, versions)

        return final_results, versions

    def generate_results(self, all_warnings_tracking: Dict, versions: List[Dict]):
        """生成匹配结果"""
        warnings_by_origin = {}

        # 统计修复状态
        #fix_stats_by_version = {}

        for warning_id, tracking in all_warnings_tracking.items():
            origin_version = tracking['origin_version']

            if origin_version not in warnings_by_origin:
                warnings_by_origin[origin_version] = []
                # fix_stats_by_version[origin_version] = {
                #     'fixed': 0,
                #     'non_fix': 0,
                #     'unknown': 0,
                #     'true_positive': 0,
                #     'false_positive': 0
                # }

            warnings_by_origin[origin_version].append({
                'warning': tracking['warning'],
                'final_status': tracking['status'],
                'origin_version': tracking['origin_version'],
                'disappeared_version': tracking.get('disappeared_version'),
                'true_positive_version': tracking.get('true_positive_version'),
                'match_history': tracking['match_history'],
                'fix_status': tracking.get('fix_status'),
                'fix_reason': tracking.get('fix_reason'),
                'diff_file': tracking.get('diff_file')
            })

            # 更新统计
            # if tracking['status'] == 'true_positive':
            #     fix_stats_by_version[origin_version]['true_positive'] += 1
            #     fix_type = tracking.get('fix_status', 'unknown')
            #     if fix_type in fix_stats_by_version[origin_version]:
            #         fix_stats_by_version[origin_version][fix_type] += 1
            # elif tracking['status'] == 'false_positive':
            #     fix_stats_by_version[origin_version]['false_positive'] += 1

        # 生成版本统计
        version_stats = {}
        for version in versions:
            version_name = version['name']
            if version_name in warnings_by_origin:
                warnings = warnings_by_origin[version_name]
                true_count = sum(1 for w in warnings if w['final_status'] == 'true_positive')
                false_count = sum(1 for w in warnings if w['final_status'] == 'false_positive')
                # fixed_count = sum(1 for w in warnings if w.get('fix_status') == 'fixed')
                # non_fix_count = sum(1 for w in warnings if w.get('fix_status') == 'non_fix')
                # unknown_count = sum(1 for w in warnings if w.get('fix_status') == 'unknown')
                #
                # fix_rate = fixed_count / true_count if true_count > 0 else 0

                version_stats[version_name] = {
                    'total_warnings': len(warnings),
                    'true_positives': true_count,
                    'false_positives': false_count,
                    # 'fixed_warnings': fixed_count,
                    # 'non_fix_warnings': non_fix_count,
                    # 'unknown_status_warnings': unknown_count,
                    # 'fix_rate': fix_rate
                }
            else:
                version_stats[version_name] = {
                    'total_warnings': 0,
                    'true_positives': 0,
                    'false_positives': 0,
                    # 'fixed_warnings': 0,
                    # 'non_fix_warnings': 0,
                    # 'unknown_status_warnings': 0,
                    # 'fix_rate': 0
                }

        # 计算总体统计
        total_true_positives = sum(1 for t in all_warnings_tracking.values() if t['status'] == 'true_positive')
        total_false_positives = sum(1 for t in all_warnings_tracking.values() if t['status'] == 'false_positive')

        # 计算修复统计
        # true_positives_by_fix = {
        #     'fixed': sum(1 for t in all_warnings_tracking.values()
        #                  if t['status'] == 'true_positive' and t.get('fix_status') == 'fixed'),
        #     'non_fix': sum(1 for t in all_warnings_tracking.values()
        #                    if t['status'] == 'true_positive' and t.get('fix_status') == 'non_fix'),
        #     'unknown': sum(1 for t in all_warnings_tracking.values()
        #                    if t['status'] == 'true_positive' and t.get('fix_status') == 'unknown')
        # }
        #
        # fix_rate = true_positives_by_fix['fixed'] / total_true_positives if total_true_positives > 0 else 0

        results = {
            'all_warnings': all_warnings_tracking,
            'warnings_by_origin': warnings_by_origin,
            'version_statistics': version_stats,
            #'fix_statistics_by_version': fix_stats_by_version,
            'overall_statistics': {
                'total_warnings': len(all_warnings_tracking),
                'total_true_positives': total_true_positives,
                'total_false_positives': total_false_positives,
                # 'true_positives_by_fix': true_positives_by_fix,
                # 'fix_rate': fix_rate
            }
        }

        return results

    def save_results(self, final_results: Dict, output_dir: str, versions: List[Dict]):
        os.makedirs(output_dir, exist_ok=True)
        all_warnings_for_project = []
        warnings_tracking = final_results['all_warnings']  # 从 final_results 中获取

        # 遍历所有版本（
        for idx, version in enumerate(versions):
            if version == versions[-1]:
                continue

            version_name = version['name']
            commit_id = version.get('commit_id')
            original_warnings = version['warnings']  # 该版本原始警告列表

            simplified_list = []

            for warning in original_warnings:
                warning_id = warning['unique_id']
                tracking = warnings_tracking.get(warning_id, {})

                # 获取 diff 内容
                diff_content = None
                diff_file_path = tracking.get('diff_file')
                if diff_file_path and os.path.exists(diff_file_path):
                    try:
                        with open(diff_file_path, 'r', encoding='utf-8') as f:
                            diff_content = f.read()
                    except Exception:
                        pass

                simplified = {
                    "project_name": warning.get('project_name'),
                    "version": version_name,
                    "commit_id": commit_id,
                    "origin_version": tracking.get('origin_version', version_name),
                    "disappeared_version": tracking.get('disappeared_version'),
                    "tool": warning.get('tool'),
                    "cwe": warning.get('cwe'),
                    "path": warning.get('filename'),
                    "line_number": warning.get('line_number'),
                    "slice": None,
                    "label": "true_positive" if tracking.get('status') == 'true_positive' else "false_positive",
                    "fix_status": tracking.get('fix_status'),
                    "fix_reason": tracking.get('fix_reason'),
                    "diff": diff_content
                }
                simplified_list.append(simplified)
                all_warnings_for_project.append(simplified)

            # 计算该版本的统计信息
            total = len(simplified_list)
            true_pos = sum(1 for w in simplified_list if w['label'] == 'true_positive')
            false_pos = total - true_pos

            version_result = {
                'statistics': {
                    'total': total,
                    'true_positives': true_pos,
                    'false_positives': false_pos
                },
                'version': version_name,
                'warnings': simplified_list,

            }
            safe_filename = version_name.replace(' ', '_').replace('.', '_')
            version_file = os.path.join(output_dir, f'{safe_filename}_simplified.json')
            with open(version_file, 'w', encoding='utf-8') as f:
                json.dump(version_result, f, indent=2, ensure_ascii=False)

        # 计算项目合并文件的统计信息
        total = len(all_warnings_for_project)
        true_pos = sum(1 for w in all_warnings_for_project if w['label'] == 'true_positive')
        false_pos = total - true_pos

        project_name = versions[0]['name'].split('-')[0] if versions else 'unknown'
        project_total = {
            'statistics': {
                'total': total,
                'true_positives': true_pos,
                'false_positives': false_pos
            },
            'project': project_name,
            'warnings': all_warnings_for_project,

        }
        project_total_file = os.path.join(output_dir, 'project_all_warnings.json')
        with open(project_total_file, 'w', encoding='utf-8') as f:
            json.dump(project_total, f, indent=2, ensure_ascii=False)

        # 生成该项目的统计文件
        statistics = {
            'project': project_name,
            'total_warnings': len(all_warnings_for_project),
            'true_positives': sum(1 for w in all_warnings_for_project if w['label'] == 'true_positive'),
            'false_positives': sum(1 for w in all_warnings_for_project if w['label'] == 'false_positive')
        }
        stats_file = os.path.join(output_dir, 'statistics.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(statistics, f, indent=2, ensure_ascii=False)


def main():
    base_path = r"D:\大创参考文献阅读\匹配代码"
    tools = ["bandit",
             "codeql",
             "horusec",
             "pylint",
             "semgrep"


             ]
    projects = [
         "ansible", "bandit"
        , "celery",
        "django",
         "flask",
         "numpy", "pandas",
         "pydantic", "scikit-learn", "tornado"
    ]
    cwe_mapping_dir = base_path

    # 定义每个项目的 commit ID 列表（按版本顺序）
    commit_ids = {
        "ansible": [
            "10cd99e9c79168dc544b2f8af12c5ffb1efc90c5",
            "0336eba0b856b88523ca79afc74223654c17666e",
            "3223e442abbf889bffc68ee1b3f066c2e500ce2c",
            "8d775ddced9ac8deb3c2f0a197da3a358070ce9e",
            "82529e534dd3edd84aba03d86b337f88c58b9982",
            "f83bccc45778a3bcf97dbb0ce38008580fb0cc88",
        ],
        "bandit": [
            "f3a18ab30bc444e62d02505419ab7059cead0853",
            "22b4226078b041a16bf05163347a66ab4dbcf3a5",
            "691f465b4bac758ea1d6dfa9b57d3881a12954fd",
            "8fd258abbac759d62863779f946d6a88e8eabb0f",
            "8ff25e07e487f143571cc305e56dd0253c60bc7b",
            "2d0b675b04c80ae42277e10500db06a0a37bae17",
        ],
        "celery": [
            "92514ac88afc4ccdff31f3a1018b04499607ca1e",
            "b3cd4988467b14c61d42eaae691ad2ab04923eff",
            "9ad7d54a25b456111bbce105ed7c654c8ff42263",
            "e73b71ed2090e83765b14162cadde771c6b520ed",
            "088c39c0f78b23a9cdf8d1c9e265ea64d02cfd86",
            "273186043cb93bcb2ce82886b54bfbcd7ddb3459",
        ],
        "django": [
            "deec9b933ee8496274e4c53217a38f31cb59a27f",
            "c499184f198df8deb8b5f7282b679babef8384ff",
            "3d3d7f5052edb99bafaa5a2f1a7dd5b968643727",
            "9e7cc2b628fe8fd3895986af9b7fc9525034c1b0",
            "c941d0deec0ea08a30670be0fac879f2372f071b",
            "3cff3209e35a560f94801d428cf7f2a3ecb2a051",
        ],
        "flask": [
            "735a4701d6d5e848241e7d7535db898efb62d400",
            "f622b1cadea2bed4ea4cc476695e9c181ec5da11",
            "c12a5d874c5a014495eb2db8a73f40037bc813ac",
            "ab8149664182b662453a563161aa89013c806dc9",
            "7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1",
            "2c1b30d0503cfb064f1cb252e6614a06915a362a",
        ],
        "numpy": [
            "1d49c7f7ff527c696fc26ab2278ad51632a66660",
            "48606ab22bfdb0e9d7ec4ed5eef984b873b7796d",
            "7469245786b57405b7ae264b386400061b3b25d3",
            "3b377854e8b1a55f15bda6f1166fe9954828231b",
            "bc5e4f811db9487a9ea1618ffb77a33b3919bb8e",
            "1458b9e79d1a5755eae9adcb346758f449b6b430",
        ],
        "pandas": [
            "a671b5a8bf5dd13fb19f0e88edc679bc9e15c673",
            "f538741432edf55c6b9fb5d0d496d2dd1d7c2457",
            "d9cdd2ee5a58015ef6f4d15c7226110c9aab8140",
            "0691c5cf90477d3503834d983f69350f250a6ff7",
            "c888af6d0bb674932007623c0867e1fbd4bdc2c6",
            "9c8bc3e55188c8aff37207a74f1dd144980b8874",
        ],
        "pydantic": [
            "9f48fc28db791ad15e389c3c0bf7dcbdd81dd0eb",
            "ed92d0a921d3464f08c5aa67dcbd262bf67110b1",
            "c326748b0119f12e284c280825d4ab6d3576643c",
            "bff747748e57c0db384dbd0df886fa623fa3a703",
            "5f033e46c54fea1b59b6894d6527daf49475e690",
            "1a8850d101e67d2744ba8c6286e1172d7cd89d0b",
        ],
        "scikit-learn": [
            "46b5f541138458803e39f9ce5810878849e4ecf7",
            "4023f7f2f341e331547c69a9ecb690197a52890b",
            "156ef141f3b270edb06c8ae9af37c55253c0aabe",
            "f159b78dc59f250cdde8fe391a21f0bc871960ad",
            "5194440b5d41e73ff436c45e35aa1476223f753c",
            "25dee604bae18205b01548348388baf7a1cdfe0e",
        ],
        "tornado": [
            "e4d698433b44f350d4908da9ca2cac475c92dfdc",
            "b3f2a4bb6fb55f6b1b1e890cdd6332665cfe4a75",
            "2a0e1d13b5222dca4388c0ec8a4bb74ea6fa4af2",
            "a5ecfab15e52202a46d34638aad93cddca86d87b",
            "bfe748948581fff5fef41d6297bcf5baf6915dd6",
            "547e6d86972238f1f5333a85f12b17fb33626899",
        ],
    }

    global_warnings = []  # 用于收集所有项目的警告

    for tool in tools:
        for project in projects:
            print(f"\n{'=' * 80}")
            print(f"开始处理: 工具={tool}, 项目={project}")
            print('=' * 80)

            warning_dir = os.path.join(base_path, "warning_set", tool, project)
            source_base_dir = os.path.join(base_path, "source_code", project)
            output_dir = os.path.join(base_path, "results", tool, project)

            if not os.path.exists(warning_dir):
                print(f"警告: 警告目录不存在，跳过 {tool}/{project}: {warning_dir}")
                continue

            json_files = glob.glob(os.path.join(warning_dir, "*.json"))
            if not json_files:
                print(f"警告: 未找到 JSON 文件，跳过 {tool}/{project}")
                continue

            # 版本提取函数（用于排序）
            def extract_version_for_sorting(filepath):
                basename = os.path.basename(filepath)
                for t in tools:
                    if basename.startswith(t + '_'):
                        basename = basename[len(t) + 1:]
                        break
                if basename.endswith(".json"):
                    basename = basename[:-5]
                parts = basename.rsplit('-', 1)
                version_str = parts[1] if len(parts) >= 2 else basename
                return version_str

            # 构建 (文件路径, 版本号) 列表并排序
            file_version_pairs = [(f, extract_version_for_sorting(f)) for f in json_files]
            if HAS_PACKAGING:
                file_version_pairs.sort(key=lambda x: pkg_version.parse(x[1]))
            else:
                file_version_pairs.sort(key=lambda x: x[1])

            version_files = [pair[0] for pair in file_version_pairs]
            print(f"找到 {len(version_files)} 个版本文件:")
            for f in version_files:
                print(f"  {os.path.basename(f)}")

            if not os.path.exists(source_base_dir):
                print(f"警告: 源代码目录不存在，跳过 {tool}/{project}: {source_base_dir}")
                continue

            os.makedirs(output_dir, exist_ok=True)

            enhanced_matcher = FixMatcher(
                matching_threshold=3,
                context_lines=3,
                snippet_similarity=0.9,
                hash_size=20,
                cwe_mapping_dir=cwe_mapping_dir
            )

            try:
                # 获取该项目的 commit 列表（按版本顺序）
                commit_list = commit_ids.get(project, [])
                results, versions = enhanced_matcher.run_matching(
                    version_files, source_base_dir, output_dir, commit_list
                )
                # 输出统计
                print("\n" + "=" * 80)
                print("匹配最终统计")
                print("=" * 80)
                overall = results['overall_statistics']
                print(f"\n总体统计:")
                print(f"  总警告数: {overall['total_warnings']}")
                print(f"  真实警告: {overall['total_true_positives']}")
                print(f"  误报: {overall['total_false_positives']}")
                if 'global_match_statistics' in results:
                    match_stats = results['global_match_statistics']
                    total_matches = sum(match_stats.values())
                    if total_matches > 0:
                        print(f"\n匹配算法分布:")
                        for match_type, count in match_stats.items():
                            percentage = (count / total_matches) * 100
                            print(f"  {match_type}: {count} ({percentage:.2f}%)")
                print("\n")
            except Exception as e:
                print(f"处理 {tool}/{project} 时出错: {e}")
                continue

            # 收集该项目总警告（合并JSON）
            project_total_file = os.path.join(output_dir, 'project_all_warnings.json')
            if os.path.exists(project_total_file):
                with open(project_total_file, 'r', encoding='utf-8') as f:
                    project_data = json.load(f)
                global_warnings.extend(project_data['warnings'])

        # 所有项目处理完后，生成工具统计
        tool_total_warnings = 0
        tool_true_positives = 0
        tool_false_positives = 0
        for project in projects:
            stats_file = os.path.join(base_path, "results", tool, project, 'statistics.json')
            if os.path.exists(stats_file):
                with open(stats_file, 'r', encoding='utf-8') as f:
                    stats = json.load(f)
                    tool_total_warnings += stats.get('total_warnings', 0)
                    tool_true_positives += stats.get('true_positives', 0)
                    tool_false_positives += stats.get('false_positives', 0)
        tool_stats = {
            'tool': tool,
            'total_warnings': tool_total_warnings,
            'true_positives': tool_true_positives,
            'false_positives': tool_false_positives
        }
        tool_stats_file = os.path.join(base_path, "results", tool, 'tool_statistics.json')
        with open(tool_stats_file, 'w', encoding='utf-8') as f:
            json.dump(tool_stats, f, indent=2, ensure_ascii=False)
        print(f"工具 {tool} 的统计汇总已保存到: {tool_stats_file}")


    # 保存全局总JSON
    global_total_file = os.path.join(base_path, 'all_warnings.json')
    global_total = {
        'warnings': global_warnings,
        'statistics': {
            'total': len(global_warnings),
            'true_positives': sum(1 for w in global_warnings if w['label'] == 'true_positive'),
            'false_positives': sum(1 for w in global_warnings if w['label'] == 'false_positive')
        }
    }
    with open(global_total_file, 'w', encoding='utf-8') as f:
        json.dump(global_total, f, indent=2, ensure_ascii=False)
    print(f"\n全局总JSON已保存到: {global_total_file}")
    print("\n所有工具和项目处理完成！")


if __name__ == "__main__":
    main()