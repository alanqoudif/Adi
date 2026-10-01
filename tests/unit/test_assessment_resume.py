
from kai.config.models import KaiConfig
from kai.knowledge.observations import Observation, ObservationType
from kai.scope.models import AssessmentMode, Scope


def test_assessment_resumes_with_prior_observations(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from kai.assessment import Assessment

    config = KaiConfig()
    config.runtime.type = "mock"

    scope = Scope(name="resume-test", mode=AssessmentMode.LAB, targets=["lab.local"])
    assessment = Assessment.create(scope, config, project_root=tmp_path)
    assessment.workspace.record_observation(
        Observation(
            type=ObservationType.OPEN_PORT,
            subject="lab.local:80",
            value={"host": "lab.local", "port": 80, "protocol": "tcp", "service": "http"},
            source="nmap",
        )
    )
    assessment_id = assessment.id

    resumed = Assessment.resume(assessment_id, config, project_root=tmp_path)
    assert resumed.id == assessment_id
    services = resumed.workspace.list_services()
    assert len(services) == 1
    assert services[0].port == 80

    assert assessment_id in Assessment.list_ids(tmp_path)
