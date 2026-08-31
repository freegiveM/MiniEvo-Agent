"""TaskStore 的连接生命周期回归测试。

背景：`with sqlite3.connect(...) as conn:` 只管事务边界，不关闭连接。
早先 TaskStore._connect 直接返回裸 Connection，导致每次数据库操作泄漏一个
文件句柄；Windows 上表现为测试 tearDown 删除临时 .db 时抛
PermissionError [WinError 32]（60 个测试里 40 个受影响）。

这里的测试锁住修复后的语义，防止有人改回裸 connect 时问题静默复发。
"""
import gc
import os
import sqlite3
import tempfile
import unittest

from evoagent.store import TaskStore


class StoreConnectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_connect_context_closes_connection_on_exit(self):
        with self.store._connect() as conn:
            conn.execute("SELECT 1")
        # 连接已归还：再用同一个对象应当报 ProgrammingError。
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")

    def test_connect_context_closes_connection_even_when_body_raises(self):
        captured = {}
        with self.assertRaises(ValueError):
            with self.store._connect() as conn:
                captured["conn"] = conn
                raise ValueError("boom")
        with self.assertRaises(sqlite3.ProgrammingError):
            captured["conn"].execute("SELECT 1")

    def test_repeated_writes_do_not_leak_handles(self):
        """真正会挡住回归的那一条：泄漏句柄时 Windows 上 os.replace 会失败。"""
        for index in range(60):
            self.store.create("leak-%d" % index, "octocat/hello", None, {"diff": ""})
        gc.collect()
        # 能重命名说明没有残留句柄占用文件（Windows 语义比 POSIX 严格）。
        moved = self.path + ".moved"
        os.replace(self.path, moved)
        os.replace(moved, self.path)


if __name__ == "__main__":
    unittest.main()
