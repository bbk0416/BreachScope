from pathlib import Path

from breachscope.release import should_exclude


def test_git_worktree_pointer_is_excluded():
    assert should_exclude('.git')
    assert should_exclude('.git/config')


def test_clean_release_build_preserves_python_distributions(tmp_path, monkeypatch):
    import scripts.build_release as cli
    dist = tmp_path / 'dist'
    dist.mkdir()
    wheel = dist / 'breachscope-2.0.0-py3-none-any.whl'
    sdist = dist / 'breachscope-2.0.0.tar.gz'
    wheel.write_bytes(b'wheel')
    sdist.write_bytes(b'sdist')
    (dist / 'old-source.zip').write_bytes(b'old')
    (dist / 'SHA256SUMS.txt').write_text('old', encoding='utf-8')
    (dist / 'release_manifest.json').write_text('{}', encoding='utf-8')
    monkeypatch.setattr(cli, 'build_release_bundle', lambda repo, out: {'dist_dir': str(out), 'artifacts': []})
    monkeypatch.setattr(cli, 'parse_args', lambda: type('Args', (), {'clean': True, 'dist': str(dist), 'repo_root': str(tmp_path), 'json': False})())
    assert cli.main() == 0
    assert wheel.read_bytes() == b'wheel'
    assert sdist.read_bytes() == b'sdist'
    assert not (dist / 'old-source.zip').exists()
    assert not (dist / 'SHA256SUMS.txt').exists()
    assert not (dist / 'release_manifest.json').exists()
