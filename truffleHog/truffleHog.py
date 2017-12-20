#!/usr/bin/env python
# -*- coding: utf-8 -*-

import shutil
import sys
import math
import datetime
import argparse
import tempfile
import os
import json
import stat
import re
from regexChecks import regexes
from git import Repo


class Issue(object):
    def __init__(self, branch, commit, blob, reason, indexes_in_diff):
        self.branch = branch
        self.commit = commit
        self.blob = blob
        self.path = blob.b_path if blob.b_path else blob.a_path
        self.reason = reason
        self.indexes_in_diff = indexes_in_diff
        self._diff = None
        self._strings_found = None
        self._highlighted_diff = None

    @property
    def commit_hash(self):
        return self.commit.hexsha

    @property
    def commit_time(self):
        return datetime.datetime.fromtimestamp(self.commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

    @property
    def diff(self):
        if self._diff is None:
            self._diff = self.blob.diff.encode('utf-8', errors='replace')
        return self._diff

    @property
    def strings_found(self):
        if self._strings_found is None:
            self._strings_found = set(self.diff[s:e] for s, e in self.indexes_in_diff)
        return self._strings_found

    @property
    def highlighted_diff(self):
        if self._highlighted_diff is None:
            self._highlighted_diff = highlight_diff(self.diff, self.indexes_in_diff)
        return self._highlighted_diff

    def as_dict(self):
        return {
            'date': self.commit_time,
            'branch': self.branch,
            'commit': self.commit.message,
            'commitHash': self.commit_hash,
            'blob': self.blob,
            'path': self.path,
            'reason': self.reason,
            'indexes_in_diff': self.indexes_in_diff,
            'diff': self.diff,
            'stringsFound': self.strings_found,
            'printDiff': self.highlighted_diff,
        }


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets")
    parser.add_argument('-i', '--include_paths', type=argparse.FileType('r'), metavar='INCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), at least one of which must match a Git '
                             'object path in order for it to be scanned; lines starting with "#" are treated as '
                             'comments and are ignored. If empty or not provided (default), all Git object paths are '
                             'included unless otherwise excluded via the --exclude_paths option.')
    parser.add_argument('-x', '--exclude_paths', type=argparse.FileType('r'), metavar='EXCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), none of which may match a Git object path '
                             'in order for it to be scanned; lines starting with "#" are treated as comments and are '
                             'ignored. If empty or not provided (default), no Git object paths are excluded unless '
                             'effectively excluded via the --include_paths option.')
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.set_defaults(regex=False)
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    args = parser.parse_args()
    do_entropy = str2bool(args.do_entropy)

    # read & compile path inclusion/exclusion patterns
    path_inclusions = []
    path_exclusions = []
    if args.include_paths:
        for pattern in set(l[:-1].lstrip() for l in args.include_paths):
            if pattern and not pattern.startswith('#'):
                path_inclusions.append(re.compile(pattern))
    if args.exclude_paths:
        for pattern in set(l[:-1].lstrip() for l in args.exclude_paths):
            if pattern and not pattern.startswith('#'):
                path_exclusions.append(re.compile(pattern))

    output = find_strings(args.git_url, args.since_commit, args.max_depth, args.output_json, args.do_regex, do_entropy,
                          path_inclusions, path_exclusions)
    project_path = output["project_path"]
    shutil.rmtree(project_path, onerror=del_rw)

def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
BASE64_WORDS = re.compile(r'[A-Za-z0-9+/=]{20,}')
HEX_CHARS = "1234567890abcdefABCDEF"
HEX_WORDS = re.compile(r'[A-Fa-f0-9]{20,}')

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path

def print_results(printJson, issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    commitHash = issue['commitHash']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True, indent=4))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")


def merge_ranges(ranges):
    """Return a generator over the non-overlapping/non-adjacent ranges, in order.

    >>> ranges = [(-10, -4), (0, 0), (1, 5), (1, 5), (-5, 0), (1, 6), (-10, -5), (9, 10), (2, 6), (6, 8)]
    >>> sorted(ranges)
    [(-10, -5), (-10, -4), (-5, 0), (0, 0), (1, 5), (1, 5), (1, 6), (2, 6), (6, 8), (9, 10)]
    >>> list(merge_ranges(ranges))
    [(-10, 0), (1, 8), (9, 10)]
    >>> list(merge_ranges([]))
    []

    :param ranges: iterable of range pairs in the form (start, stop)
    :return: generator yielding the non-overlapping and non-adjecent range pairs, in order
    """
    ranges = sorted(ranges)
    if not ranges:
        return
    current_start, current_stop = ranges[0]
    for start, stop in ranges[1:]:
        if start > current_stop:
            yield current_start, current_stop
            current_start, current_stop = start, stop
        else:
            current_stop = max(current_stop, stop)
    yield current_start, current_stop


def highlight_diff(printableDiff, ranges):
    """Return `printableDiff` with each highlight position in `ranges` surrounded by bash color control characters.

    The `ranges` parameter should be an iterable of `(<start_index>, <end_index>)` tuples designating where highlighted
    index ranges should occur. These ranges are first consolidated such that overlapping and adjacent ranges are
    combined before `printableDiff` is highlighted by inserting the bash color control character into those ranges.

    >>> highlight_diff('foobar foo!', [(0, 3), (3, 6)])
    '\\x1b[93mfoobar\\x1b[0m foo!'
    >>> highlight_diff('foobar foo!', [(0, 3), (3, 6), (3, 10)])
    '\\x1b[93mfoobar foo\\x1b[0m!'

    :param printableDiff: string to highlight by inserting bash color control characters at the given index ranges
    :param ranges: iterable of `(<start_index>, <end_index>)` tuples indicating where to highlight `printableDiff`
    :return: string resulting from insertion of bash color highlights into `printableDiff` at the given index ranges
    """
    ranges = list(merge_ranges(r for r in ranges if r[0] != r[1]))
    prev_end = 0
    highlighted_diff = ''
    for start, end in ranges:
        highlighted_diff += '{unmatched_text}{hl_start}{hl_text}{hl_end}'.format(
            unmatched_text=printableDiff[prev_end:start],
            hl_start=bcolors.WARNING,
            hl_text=printableDiff[start:end],
            hl_end=bcolors.ENDC)
        prev_end = end
    highlighted_diff += printableDiff[prev_end:]
    return highlighted_diff


def get_ranges(string, substring):
    """Return generator over the ranges, as tuples of `(<start_index>, <end_index>)`, where `substring` occurs in `string`.

    Note that `substring` must be a non-empty string.

    >>> list(get_ranges('foobar foo', ''))
    []
    >>> list(get_ranges('foobar foo', 'bar'))
    [(3, 6)]
    >>> list(get_ranges('foobar foo', 'foo'))
    [(0, 3), (7, 10)]

    :param string: the string to search for occurrences of `substring`
    :param substring: the (non-empty) substring for which to search for occurrences of within `string`
    :return: a generator yielding tuples of `(<start_index>, <end_index>)` where `substring` occurs within `string`
    """
    match_len = len(substring)
    if match_len == 0:
        return
    start = string.find(substring)
    while start != -1:
        end = start + match_len
        yield start, end
        start = string.find(substring, end)


def find_entropy(printableDiff):
    finding_indexes = []
    for match in BASE64_WORDS.finditer(printableDiff):
        if shannon_entropy(match.group(), BASE64_CHARS) > 4.5:
            finding_indexes.append((match.start(), match.end()))
    for match in HEX_WORDS.finditer(printableDiff):
        if shannon_entropy(match.group(), HEX_CHARS) > 3.0:
            finding_indexes.append((match.start(), match.end()))
    return 'High Entropy', finding_indexes


def regex_check(printableDiff):
    for key in regexes:
        finding_indexes = list((m.start(), m.end()) for m in regexes[key].finditer(printableDiff) if len(m.group()))
        if finding_indexes:
            yield key, finding_indexes


def path_included(blob, include_patterns=None, exclude_patterns=None):
    """Check if the diff blob object should included in analysis.

    If defined and non-empty, `include_patterns` has precedence over `exclude_patterns`, such that a blob that is not
    matched by any of the defined `include_patterns` will be excluded, even when it is not matched by any of the defined
    `exclude_patterns`. If either `include_patterns` or `exclude_patterns` are undefined or empty, they will have no
    effect, respectively. All blobs are included by this function when called with default arguments.

    :param blob: a Git diff blob object
    :param include_patterns: iterable of compiled regular expression objects; when non-empty, at least one pattern must
     match the blob object for it to be included; if empty or None, all blobs are included, unless excluded via
     `exclude_patterns`
    :param exclude_patterns: iterable of compiled regular expression objects; when non-empty, _none_ of the patterns may
     match the blob object for it to be included; if empty or None, no blobs are excluded if not otherwise
     excluded via `include_patterns`
    :return: False if the blob is _not_ matched by `include_patterns` (when provided) or if it is matched by
    `exclude_patterns` (when provided), otherwise returns True
    """
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True


def find_strings(git_url, since_commit=None, max_depth=None, printJson=False, do_regex=False, do_entropy=True,
                 path_inclusions=None, path_exclusions=None):
    output = {"entropicDiffs": []}
    project_path = clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    foundIssues = []

    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits(max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            if prev_commit:
                #avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                # diff = prev_commit.diff(curr_commit, create_patch=True, unified=0)
                diff = curr_commit.diff(prev_commit, create_patch=True, unified=0)
                for blob in diff:
                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    if not path_included(blob, path_inclusions, path_exclusions):
                        continue
                    if do_entropy:
                        reason, finding_indexes = find_entropy(printableDiff)
                        if finding_indexes:
                            entropy_issue = Issue(branch_name, prev_commit, blob, reason, finding_indexes)
                            foundIssues.append(entropy_issue)
                            print_results(printJson, entropy_issue.as_dict())
                    if do_regex:
                        for reason, finding_indexes in regex_check(printableDiff):
                            regex_issue = Issue(branch_name, prev_commit, blob, reason, finding_indexes)
                            foundIssues.append(regex_issue)
                            print_results(printJson, regex_issue.as_dict())
            prev_commit = curr_commit
    output["project_path"] = project_path
    return output

if __name__ == "__main__":
    main()
