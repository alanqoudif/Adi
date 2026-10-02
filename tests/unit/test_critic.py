import pytest

from adi.agent.critic import Critic, CriticDecision, CriticReview
from adi.llm.mock import MockLLM


@pytest.mark.asyncio
async def test_critic_returns_scripted_accept():
    llm = MockLLM()
    llm.script_structured(CriticReview(decision=CriticDecision.ACCEPT, concerns=[]))
    critic = Critic(llm)

    review = await critic.review("possible IDOR", "broken_object_authorization", ["user_b got user_a's order"])
    assert review.decision == CriticDecision.ACCEPT


@pytest.mark.asyncio
async def test_critic_can_request_more_evidence():
    llm = MockLLM()
    llm.script_structured(CriticReview(
        decision=CriticDecision.NEEDS_MORE_EVIDENCE,
        concerns=["ownership of the object was never independently confirmed"],
        additional_validation_needed=["confirm user_a actually owns object 1 before comparing"],
    ))
    critic = Critic(llm)

    review = await critic.review("possible IDOR", "broken_object_authorization", ["ambiguous evidence"])
    assert review.decision == CriticDecision.NEEDS_MORE_EVIDENCE
    assert review.additional_validation_needed


@pytest.mark.asyncio
async def test_critic_prompt_includes_bounded_evidence_not_everything():
    llm = MockLLM()
    llm.script_structured(CriticReview(decision=CriticDecision.ACCEPT))
    critic = Critic(llm)

    await critic.review("title", "category", [f"evidence {i}" for i in range(50)])
    prompt = llm.calls[0][-1].content
    # bounded to 15 summaries, not all 50
    assert prompt.count("evidence ") <= 16
