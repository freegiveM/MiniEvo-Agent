"""存储后端工厂：删掉 Postgres 后必须显式报错，不能静默降级。"""
import os
import tempfile
import unittest

from evoagent.store import TaskStore, create_store


class StoreFactoryTests(unittest.TestCase):

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)

    def tearDown(self):
        os.unlink(self.path)

    def test_empty_url_gives_a_sqlite_store(self):
        self.assertIsInstance(create_store("", self.path), TaskStore)

    def test_a_postgres_url_raises_instead_of_falling_back(self):
        """这是这个文件存在的理由。

        静默降级到 SQLite 的话，配了 Postgres 的人会以为数据写进了
        Postgres，实际写在本地文件里。出问题时排查方向全错，而且
        错得没有任何提示。报错难看但诚实。
        """
        for url in ("postgres://u:p@h/db", "postgresql://u:p@h/db"):
            with self.assertRaises(NotImplementedError):
                create_store(url, self.path)

    def test_the_error_says_what_to_do(self):
        """报错要给出下一步，不然用户只知道坏了不知道怎么办。"""
        with self.assertRaises(NotImplementedError) as caught:
            create_store("postgres://u:p@h/db", self.path)
        self.assertIn("EVOAGENT_DATABASE_URL", str(caught.exception))

    def test_a_sqlite_url_shaped_string_is_not_mistaken_for_postgres(self):
        self.assertIsInstance(create_store("sqlite:///x.db", self.path), TaskStore)


if __name__ == "__main__":
    unittest.main()
