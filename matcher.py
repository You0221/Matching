import json
import os
from typing import List, Dict, Tuple, Optional
from 匹配算法 import Matcher
from fix_analyzer import ASTFixAnalyzer, FixStatus

class FixMatcher(Matcher):

    def __init__(self, matching_threshold: int = 3, context_lines: int = 3,
                 snippet_similarity: float = 0.9, hash_size: int = 20):
        super().__init__(matching_threshold, context_lines, snippet_similarity, hash_size)
        self.fix_analyzer = ASTFixAnalyzer()

    def analyze_fix_status(self, parent_warning: Dict,
                           parent_source_dir: str, child_source_dir: str) -> Tuple[FixStatus, str, Optional[str]]:
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
            diff_changes = self.fix_analyzer.analyze_diff_changes(parent_file_path, child_file_path)

            # 使用修复分析
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
        """
        匹配两个版本间的警告，并分析修复状态
        """
        # 先使用父类的匹配方法
        match_result = super().match_warnings_between_versions(
            parent_warnings, child_warnings, parent_source_dir, child_source_dir
        )

        print(f"\n开始修复状态分析...")

        fixed_warnings = []
        non_fix_warnings = []
        unknown_status_warnings = []

        for parent_warning in match_result['true_positives']:
            # 分析修复状态
            status, reason, child_file_path = self.analyze_fix_status(
                parent_warning, parent_source_dir, child_source_dir
            )

            # 添加修复状态信息到警告对象
            warning_with_fix = parent_warning.copy()
            warning_with_fix['fix_status'] = status.value
            warning_with_fix['fix_reason'] = reason
            warning_with_fix['child_file_path'] = child_file_path
            warning_with_fix['fix_version'] = child_version_name

            # 分类
            if status == FixStatus.FIXED:
                fixed_warnings.append(warning_with_fix)
            elif status == FixStatus.NON_FIX:
                non_fix_warnings.append(warning_with_fix)
            else:
                unknown_status_warnings.append(warning_with_fix)

        print(f"  已修复警告: {len(fixed_warnings)} 个")
        print(f"  未修复警告: {len(non_fix_warnings)} 个")
        print(f"  未知警告: {len(unknown_status_warnings)} 个")

        # 更新匹配结果
        match_result['fixed_warnings'] = fixed_warnings
        match_result['non_fix_warnings'] = non_fix_warnings
        match_result['unknown_status_warnings'] = unknown_status_warnings

        # 更新统计信息
        match_result['fix_statistics'] = { # type: ignore
            'fixed': len(fixed_warnings),
            'non_fix': len(non_fix_warnings),
            'unknown': len(unknown_status_warnings)
        }

        # 添加版本信息
        match_result['parent_version'] = parent_version_name # type: ignore
        match_result['child_version'] = child_version_name # type: ignore

        return match_result

    def run_matching(self, version_files: List[str],
                    source_base_dir: str, output_dir: str):
        """
        运行带有修复分析的匹配算法
        """
        # 加载版本数据
        versions = []
        for file_path in version_files:
            warnings = self.load_warnings(file_path)
            version_name = os.path.basename(file_path).replace('bandit_', '').replace('.json', '')
            source_dir = os.path.join(source_base_dir, version_name)
            versions.append({
                'name': version_name,
                'file': file_path,
                'warnings': warnings,
                'count': len(warnings),
                'source_dir': source_dir
            })

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

            # 对于每个父版本警告，跟踪它是否已经在某个版本中消失了
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
                for fix_type, count in match_result.get('fix_statistics', {}).items():
                    if fix_type in global_fix_stats:
                        global_fix_stats[fix_type] += count

                # 处理 false_positives - 这些警告在子版本中仍然存在
                for false_positive in match_result['false_positives']:
                    parent_warning = false_positive['parent_warning']
                    child_warning = false_positive['child_warning']
                    warning_id = parent_warning['unique_id']

                    # 记录出现在这个版本
                    if child_version_name not in warnings_tracking[warning_id]['appearance_history']:
                        warnings_tracking[warning_id]['appearance_history'].append(child_version_name)

                    # 记录匹配历史
                    warnings_tracking[warning_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': false_positive['match_type'],
                        'status': 'false_positive',
                        'matched_child_warning': child_warning
                    })

                # 处理已修复的警告 - 这些警告在子版本中消失了
                for fixed_warning in match_result.get('fixed_warnings', []):
                    warning_id = fixed_warning['unique_id']
                    warnings_tracking[warning_id]['fix_status'] = 'fixed'
                    warnings_tracking[warning_id]['fix_reason'] = fixed_warning.get('fix_reason', '')
                    warnings_tracking[warning_id]['disappeared_version'] = child_version_name
                    warnings_tracking[warning_id]['fix_version'] = child_version_name
                    warning_disappeared[warning_id] = True  # 标记为消失，不再参与后续匹配

                    warnings_tracking[warning_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': 'none',
                        'status': 'fixed',
                        'matched_child_warning': None,
                        'fix_reason': fixed_warning.get('fix_reason', '')
                    })

                # 处理未修复的警告
                for non_fix_warning in match_result.get('non_fix_warnings', []):
                    warning_id = non_fix_warning['unique_id']
                    warnings_tracking[warning_id]['fix_status'] = 'non_fix'
                    warnings_tracking[warning_id]['fix_reason'] = non_fix_warning.get('fix_reason', '')
                    warnings_tracking[warning_id]['disappeared_version'] = child_version_name
                    warning_disappeared[warning_id] = True  # 标记为消失，不再参与后续匹配

                    warnings_tracking[warning_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': 'none',
                        'status': 'non_fix',
                        'matched_child_warning': None,
                        'fix_reason': non_fix_warning.get('fix_reason', '')
                    })

                # 处理状态未知的警告
                for unknown_warning in match_result.get('unknown_status_warnings', []):
                    warning_id = unknown_warning['unique_id']
                    warnings_tracking[warning_id]['fix_status'] = 'unknown'
                    warnings_tracking[warning_id]['fix_reason'] = unknown_warning.get('fix_reason', '')
                    warnings_tracking[warning_id]['disappeared_version'] = child_version_name
                    warning_disappeared[warning_id] = True  # 标记为消失，不再参与后续匹配

                    warnings_tracking[warning_id]['match_history'].append({
                        'parent_version': version_key,
                        'child_version': child_version_name,
                        'match_type': 'none',
                        'status': 'unknown',
                        'matched_child_warning': None,
                        'fix_reason': unknown_warning.get('fix_reason', '')
                    })

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
        fix_stats_by_version = {}

        for warning_id, tracking in all_warnings_tracking.items():
            origin_version = tracking['origin_version']

            if origin_version not in warnings_by_origin:
                warnings_by_origin[origin_version] = []
                fix_stats_by_version[origin_version] = {
                    'fixed': 0,
                    'non_fix': 0,
                    'unknown': 0,
                    'true_positive': 0,
                    'false_positive': 0
                }

            warnings_by_origin[origin_version].append({
                'warning': tracking['warning'],
                'final_status': tracking['status'],
                'fix_status': tracking.get('fix_status', 'unknown'),
                'fix_reason': tracking.get('fix_reason', ''),
                'true_positive_version': tracking.get('true_positive_version'),
                'fix_version': tracking.get('fix_version'),
                'match_history': tracking['match_history']
            })

            # 更新统计
            if tracking['status'] == 'true_positive':
                fix_stats_by_version[origin_version]['true_positive'] += 1
                fix_type = tracking.get('fix_status', 'unknown')
                if fix_type in fix_stats_by_version[origin_version]:
                    fix_stats_by_version[origin_version][fix_type] += 1
            elif tracking['status'] == 'false_positive':
                fix_stats_by_version[origin_version]['false_positive'] += 1

        # 生成版本统计
        version_stats = {}
        for version in versions:
            version_name = version['name']
            if version_name in warnings_by_origin:
                warnings = warnings_by_origin[version_name]
                true_count = sum(1 for w in warnings if w['final_status'] == 'true_positive')
                false_count = sum(1 for w in warnings if w['final_status'] == 'false_positive')
                fixed_count = sum(1 for w in warnings if w.get('fix_status') == 'fixed')
                non_fix_count = sum(1 for w in warnings if w.get('fix_status') == 'non_fix')
                unknown_count = sum(1 for w in warnings if w.get('fix_status') == 'unknown')

                fix_rate = fixed_count / true_count if true_count > 0 else 0

                version_stats[version_name] = {
                    'total_warnings': len(warnings),
                    'true_positives': true_count,
                    'false_positives': false_count,
                    'fixed_warnings': fixed_count,
                    'non_fix_warnings': non_fix_count,
                    'unknown_status_warnings': unknown_count,
                    'fix_rate': fix_rate
                }
            else:
                version_stats[version_name] = {
                    'total_warnings': 0,
                    'true_positives': 0,
                    'false_positives': 0,
                    'fixed_warnings': 0,
                    'non_fix_warnings': 0,
                    'unknown_status_warnings': 0,
                    'fix_rate': 0
                }

        # 计算总体统计
        total_true_positives = sum(1 for t in all_warnings_tracking.values() if t['status'] == 'true_positive')
        total_false_positives = sum(1 for t in all_warnings_tracking.values() if t['status'] == 'false_positive')

        # 计算修复统计
        true_positives_by_fix = {
            'fixed': sum(1 for t in all_warnings_tracking.values()
                         if t['status'] == 'true_positive' and t.get('fix_status') == 'fixed'),
            'non_fix': sum(1 for t in all_warnings_tracking.values()
                           if t['status'] == 'true_positive' and t.get('fix_status') == 'non_fix'),
            'unknown': sum(1 for t in all_warnings_tracking.values()
                           if t['status'] == 'true_positive' and t.get('fix_status') == 'unknown')
        }

        fix_rate = true_positives_by_fix['fixed'] / total_true_positives if total_true_positives > 0 else 0

        results = {
            'all_warnings': all_warnings_tracking,
            'warnings_by_origin': warnings_by_origin,
            'version_statistics': version_stats,
            'fix_statistics_by_version': fix_stats_by_version,
            'overall_statistics': {
                'total_warnings': len(all_warnings_tracking),
                'total_true_positives': total_true_positives,
                'total_false_positives': total_false_positives,
                'true_positives_by_fix': true_positives_by_fix,
                'fix_rate': fix_rate
            }
        }

        return results

    def save_results(self, final_results: Dict, output_dir: str, versions: List[Dict]):
        """保存匹配结果"""
        os.makedirs(output_dir, exist_ok=True)

        # 保存完整结果
        complete_file = os.path.join(output_dir, "matching_results.json")
        with open(complete_file, 'w', encoding='utf-8') as f:
            json.dump(final_results, f, indent=2, ensure_ascii=False)
        print(f"\n已保存匹配结果到: {complete_file}")

        # 为每个版本创建单独的摘要文件
        for version in versions:
            version_name = version['name']
            if version_name in final_results['warnings_by_origin']:
                version_warnings = final_results['warnings_by_origin'][version_name]
                version_stat = final_results['version_statistics'][version_name]

                version_result = {
                    'version': version_name,
                    'statistics': version_stat,
                    'warnings': version_warnings
                }

                safe_filename = version_name.replace(' ', '_').replace('.', '_')
                output_file = os.path.join(output_dir, f'{safe_filename}_summary.json')

                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(version_result, f, indent=2, ensure_ascii=False)

        # 生成详细的文本报告
        self.generate_report(final_results, output_dir, versions)

    def generate_report(self, final_results: Dict, output_dir: str, versions: List[Dict]):
        """详细文本报告"""
        report_file = os.path.join(output_dir, "detailed_report.txt")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 120 + "\n")
            f.write("匹配详细报告\n")
            f.write("=" * 120 + "\n\n")

            # 总体统计
            overall = final_results['overall_statistics']
            f.write("总体统计:\n")
            f.write(f"  总警告数: {overall['total_warnings']}\n")
            f.write(f"  真实警告数: {overall['total_true_positives']}\n")
            f.write(f"  误报数: {overall['total_false_positives']}\n")

            if overall['total_true_positives'] > 0:
                true_positive_by_fix = overall['true_positives_by_fix']
                f.write(f"\n  修复状态分布:\n")
                f.write(
                    f"    - 已修复: {true_positive_by_fix['fixed']} ({true_positive_by_fix['fixed'] / overall['total_true_positives'] * 100:.1f}%)\n")
                f.write(
                    f"    - 未修复: {true_positive_by_fix['non_fix']} ({true_positive_by_fix['non_fix'] / overall['total_true_positives'] * 100:.1f}%)\n")
                f.write(
                    f"    - 状态未知: {true_positive_by_fix['unknown']} ({true_positive_by_fix['unknown'] / overall['total_true_positives'] * 100:.1f}%)\n")
                f.write(f"    整体修复率: {overall['fix_rate'] * 100:.1f}%\n")

            if overall['total_warnings'] > 0:
                true_positive_rate = (overall['total_true_positives'] / overall['total_warnings']) * 100
                false_positive_rate = (overall['total_false_positives'] / overall['total_warnings']) * 100
                f.write(f"\n  真实警告率: {true_positive_rate:.2f}%\n")
                f.write(f"  误报率: {false_positive_rate:.2f}%\n")

            f.write("\n" + "=" * 120 + "\n")

            # 按版本输出统计
            f.write("\n各版本统计:\n")
            f.write("-" * 120 + "\n")
            f.write(
                f"{'版本':<20} {'总警告':<8} {'真实警告':<10} {'误报':<8} {'已修复':<8} {'未修复':<10} {'修复率':<8}\n")
            f.write("-" * 120 + "\n")

            version_names = [v['name'] for v in versions]
            for version_name in version_names:
                if version_name in final_results['version_statistics']:
                    stats = final_results['version_statistics'][version_name]
                    fix_rate_percent = stats['fix_rate'] * 100 if stats['fix_rate'] > 0 else 0
                    f.write(f"{version_name:<20} {stats['total_warnings']:<8} {stats['true_positives']:<10} "
                            f"{stats['false_positives']:<8} {stats['fixed_warnings']:<8} "
                            f"{stats['non_fix_warnings']:<10} {fix_rate_percent:>6.1f}%\n")

            f.write("\n" + "=" * 120 + "\n")

            # 按版本输出警告详情
            for version_name in version_names:
                if version_name in final_results['warnings_by_origin']:
                    version_warnings = final_results['warnings_by_origin'][version_name]

                    f.write(f"\n版本: {version_name} (共 {len(version_warnings)} 个警告)\n")
                    f.write("-" * 120 + "\n")

                    # 按修复状态分组
                    warnings_by_fix_status = {
                        'fixed': [],
                        'non_fix': [],
                        'unknown': [],
                        'false_positive': []
                    }

                    for warning_info in version_warnings:
                        status = warning_info.get('fix_status', 'unknown')
                        if warning_info['final_status'] == 'false_positive':
                            warnings_by_fix_status['false_positive'].append(warning_info)
                        elif status in warnings_by_fix_status:
                            warnings_by_fix_status[status].append(warning_info)
                        else:
                            warnings_by_fix_status['unknown'].append(warning_info)

                    # 输出每种状态的警告
                    for status, warnings in warnings_by_fix_status.items():
                        if not warnings:
                            continue

                        status_label = {
                            'fixed': '已修复警告',
                            'non_fix': '未修复警告',
                            'unknown': '状态未知警告',
                            'false_positive': '误报警告'
                        }.get(status, status)

                        f.write(f"\n{status_label} ({len(warnings)} 个):\n")
                        f.write("~" * 80 + "\n")

                        for warning_idx, warning_info in enumerate(warnings, 1):
                            warning = warning_info['warning']
                            f.write(f"{warning_idx}. 警告ID: {warning['unique_id']}\n")
                            f.write(f"   文件: {warning.get('filename', 'N/A')}\n")
                            f.write(f"   行号: {warning.get('line_number', 0)}\n")
                            f.write(
                                f"   类型: {warning.get('test_name', 'N/A')} (ID: {warning.get('test_id', 'N/A')})\n")
                            f.write(f"   问题: {warning.get('issue_text', 'N/A')}\n")

                            if warning_info['final_status'] == 'true_positive':
                                f.write(f"   修复状态: {warning_info.get('fix_status', 'unknown')}\n")
                                f.write(f"   修复原因: {warning_info.get('fix_reason', '')}\n")
                                if warning_info.get('true_positive_version'):
                                    f.write(f"   修复版本: {warning_info['true_positive_version']}\n")
                            else:
                                f.write(f"   匹配状态: {warning_info['final_status']}\n")

                            # 输出匹配历史
                            if warning_info['match_history']:
                                f.write("   匹配历史:\n")
                                for match in warning_info['match_history']:
                                    f.write(f"     - {match['parent_version']} → {match['child_version']}: ")
                                    f.write(f"{match.get('match_type', 'none')}匹配, 状态: {match['status']}\n")
                                    if match.get('fix_reason'):
                                        f.write(f"       修复原因: {match['fix_reason']}\n")
                            f.write("\n")

                    f.write("\n")

        print(f"详细报告已保存到: {report_file}")


def main():
    base_path = r"D:\大创参考文献阅读\匹配代码"

    version_files = [
        os.path.join(base_path, "bandit_ansible-2.17.1rc1.json"),
        os.path.join(base_path, "bandit_ansible-2.17.4rc1.json"),
        os.path.join(base_path, "bandit_ansible-2.18.1.json"),
        #os.path.join(base_path, "bandit_ansible-2.19.0.json"),
        #os.path.join(base_path, "bandit_ansible-2.19.0b1.json"),
        #os.path.join(base_path, "bandit_ansible-2.20.0rc2.json")
    ]

    source_base_dir = os.path.join(base_path, "ansible")

    for file_path in version_files:
        if not os.path.exists(file_path):
            print(f"警告: 文件不存在: {file_path}")

    if not os.path.exists(source_base_dir):
        print(f"警告: 源代码基础目录不存在: {source_base_dir}")

    # 初始化匹配器
    enhanced_matcher = FixMatcher(
        matching_threshold=3,
        context_lines=3,
        snippet_similarity=0.9,
        hash_size=20
    )

    output_dir = os.path.join(base_path, "results")
    results, versions = enhanced_matcher.run_matching(
        version_files, source_base_dir, output_dir
    )

    # 输出最终统计
    print("\n" + "=" * 80)
    print("匹配最终统计")
    print("=" * 80)

    overall = results['overall_statistics']
    print(f"\n总体统计:")
    print(f"  总警告数: {overall['total_warnings']}")
    print(f"  真实警告: {overall['total_true_positives']}")
    print(f"  误报: {overall['total_false_positives']}")

    if overall['total_true_positives'] > 0:
        true_positive_by_fix = overall['true_positives_by_fix']
        print(f"\n  真实警告修复状态:")
        print(f"    - 已修复: {true_positive_by_fix['fixed']} "
              f"({true_positive_by_fix['fixed'] / overall['total_true_positives'] * 100:.1f}%)")
        print(f"    - 未修复: {true_positive_by_fix['non_fix']} "
              f"({true_positive_by_fix['non_fix'] / overall['total_true_positives'] * 100:.1f}%)")
        print(f"    - 状态未知: {true_positive_by_fix['unknown']} "
              f"({true_positive_by_fix['unknown'] / overall['total_true_positives'] * 100:.1f}%)")
        print(f"    整体修复率: {overall['fix_rate'] * 100:.1f}%")

    if 'global_match_statistics' in results:
        match_stats = results['global_match_statistics']
        total_matches = sum(match_stats.values())
        if total_matches > 0:
            print(f"\n匹配算法分布:")
            for match_type, count in match_stats.items():
                percentage = (count / total_matches) * 100
                print(f"  {match_type}: {count} ({percentage:.2f}%)")


if __name__ == "__main__":
    main()