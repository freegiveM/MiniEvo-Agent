import dataclasses
import os
import tempfile
import unittest
from unittest.mock import patch

from evoagent.config import Settings, load_dotenv


class DotenvTests(unittest.TestCase):
    def test_loads_valid_assignments_and_quoted_values(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("# comment\n")
            handle.write("export EVOAGENT_LLM_PROVIDER=deepseek\n")
            handle.write('EVOAGENT_DEEPSEEK_API_KEY="test-key"\n')
            handle.write("invalid line\n")
            path = handle.name
        try:
            with patch.dict(os.environ, {}, clear=True):
                load_dotenv([path])
                self.assertEqual("deepseek", os.environ["EVOAGENT_LLM_PROVIDER"])
                self.assertEqual("test-key", os.environ["EVOAGENT_DEEPSEEK_API_KEY"])
        finally:
            os.unlink(path)

    def test_process_environment_has_priority(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("EVOAGENT_LLM_PROVIDER=deepseek\n")
            path = handle.name
        try:
            with patch.dict(os.environ, {"EVOAGENT_LLM_PROVIDER": "custom"}, clear=True):
                load_dotenv([path])
                self.assertEqual("custom", os.environ["EVOAGENT_LLM_PROVIDER"])
        finally:
            os.unlink(path)


class GeneratorTokenBudgetTests(unittest.TestCase):
    """候选生成那一次调用的 token 预算。

    这个设置存在的理由是一次真实探测：默认 6000 在 deepseek-v4-flash 上
    **一条候选都产不出来**——`max_tokens` 同时封顶 reasoning + content，
    6000 全被推理吃掉，`content` 是空串、`finish_reason=length`。第 16.5
    节修了这个错误的报错文案（原来报成"模型返回了非法 JSON"），但预算本身
    没动，于是回路 A 至今一次都没真跑起来。
    """

    def _settings(self, **overrides) -> Settings:
        # Settings 是 frozen dataclass，只能靠 replace 换字段。
        return dataclasses.replace(Settings.from_env(), **overrides)

    def test_the_default_can_actually_finish_a_generation(self):
        """默认值必须大于实测耗尽的那个数。

        6000 是实测跑不完的值。默认值留在跑不完的档位上，等于让回路静默
        停在生成这一步——而那次调用照常计费。
        """
        with patch.dict(os.environ, {}, clear=True):
            self.assertGreater(
                Settings.from_env().evolution_generator_token_budget, 6000
            )

    def test_it_is_configurable_from_the_environment(self):
        with patch.dict(
            os.environ,
            {"EVOAGENT_EVOLUTION_GENERATOR_TOKEN_BUDGET": "24000"},
            clear=True,
        ):
            self.assertEqual(
                24000, Settings.from_env().evolution_generator_token_budget
            )

    def test_a_budget_too_small_to_generate_is_refused(self):
        """配一个装不下一次生成的预算要当场报错，不能等到运行时。

        运行时的表现是"调用成功、content 空串"，那是一道假装在工作的
        环节——与第 16.6 节那个门禁缺陷同一种毛病。
        """
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                self._settings(
                    evolution_generator_token_budget=1500
                ).validate_evolution()

    def test_a_sane_budget_passes_validation(self):
        with patch.dict(os.environ, {}, clear=True):
            self._settings(
                evolution_generator_token_budget=16000
            ).validate_evolution()
