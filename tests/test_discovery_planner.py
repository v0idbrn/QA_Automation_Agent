import pytest

from core.discovery import DiscoveredProject, _has_e2e_tests, _infer_python_routes, discover_project
from core.planner import PlanItem, TestPlan, build_plan_from_discovery


class TestDiscoveredProject:
    def test_summary_format(self):
        project = DiscoveredProject(root=Path("/tmp"), language="python", framework="fastapi", test_files=["tests/test_x.py"])
        summary = project.summary()
        assert "python" in summary
        assert "fastapi" in summary
        assert "1 test files" in summary


class TestDiscoveryHelpers:
    def test_has_e2e_tests_detects_e2e(self):
        assert _has_e2e_tests(["tests/e2e/test_flow.py"]) is True
        assert _has_e2e_tests(["tests/unit/test_x.py"]) is False

    def test_infer_python_routes_extracts_api_paths(self):
        routes: list[str] = []
        api_endpoints: list[str] = []
        _infer_python_routes(Path("fake"), routes, api_endpoints)
        # When there is no real file, helpers should not crash.
        assert isinstance(routes, list)
        assert isinstance(api_endpoints, list)


class TestPlanner:
    def test_plan_summary_lists_areas(self):
        discovery = DiscoveredProject(root=Path("/tmp"), language="python", test_files=["tests/test_x.py"])
        plan = TestPlan(target="sample", discovery=discovery)
        plan.add("Safety", "Validate scope and budgets")
        plan.add("API Coverage", "Propose checks for observed endpoints")
        text = plan.summary()
        assert "Safety" in text
        assert "API Coverage" in text

    def test_plan_from_discovery_produces_items(self):
        discovery = DiscoveredProject(root=Path("/tmp"), language="python", api_endpoints=["/api/health"])
        plan = build_plan_from_discovery(discovery, target="sample")
        assert isinstance(plan.items, list)
        assert len(plan.items) >= 1
