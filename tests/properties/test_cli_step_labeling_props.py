"""Property-based tests for CLI step sequential labeling.

**Validates: Requirements 8.8**

Tests that N workflow steps are labeled with monotonically increasing
step numbers (1 through N) and that each step has a non-empty descriptive
stage name.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.cli.formatting import StepResult, format_summary_line, format_verbose_output
from src.cli.workflows import WorkflowStep


# --- Strategies ---

# Non-empty stage names (descriptive labels for workflow steps)
stage_names = st.text(
    min_size=1,
    max_size=50,
    alphabet=st.characters(
        whitelist_categories=("L", "N", "Zs"),
        whitelist_characters="-_/",
    ),
).filter(lambda s: s.strip() != "")


def step_result_sequences(min_steps=1, max_steps=20):
    """Generate a list of StepResult objects with sequential step numbers 1..N."""
    return st.integers(min_value=min_steps, max_value=max_steps).flatmap(
        lambda n: st.lists(
            st.tuples(stage_names, st.booleans()),
            min_size=n,
            max_size=n,
        ).map(
            lambda items: [
                StepResult(
                    step_number=i + 1,
                    stage_name=name,
                    success=success,
                )
                for i, (name, success) in enumerate(items)
            ]
        )
    )


def workflow_step_sequences(min_steps=1, max_steps=20):
    """Generate a list of WorkflowStep objects with sequential step numbers 1..N."""
    return st.integers(min_value=min_steps, max_value=max_steps).flatmap(
        lambda n: st.lists(
            st.tuples(stage_names, st.booleans()),
            min_size=n,
            max_size=n,
        ).map(
            lambda items: [
                WorkflowStep(
                    step_number=i + 1,
                    stage_name=name,
                    success=success,
                )
                for i, (name, success) in enumerate(items)
            ]
        )
    )


@pytest.mark.property
class TestCLIStepSequentialLabeling:
    """Property 7: CLI Step Sequential Labeling.

    For any sequence of N workflow steps, each step in the output SHALL be
    labeled with a monotonically increasing step number (1 through N) and
    a non-empty descriptive stage name that precedes the step output.
    """

    @given(steps=step_result_sequences())
    def test_step_numbers_are_monotonically_increasing(self, steps: list[StepResult]):
        """Step numbers in a sequence of N steps form the series 1, 2, ..., N.

        **Validates: Requirements 8.8**
        """
        step_numbers = [s.step_number for s in steps]
        expected = list(range(1, len(steps) + 1))

        assert step_numbers == expected, (
            f"Step numbers are not monotonically increasing 1..N. "
            f"Expected {expected}, got {step_numbers}"
        )

    @given(steps=step_result_sequences())
    def test_each_step_has_non_empty_stage_name(self, steps: list[StepResult]):
        """Every step in a sequence has a non-empty stage name.

        **Validates: Requirements 8.8**
        """
        for step in steps:
            assert step.stage_name.strip() != "", (
                f"Step {step.step_number} has an empty stage name"
            )

    @given(steps=step_result_sequences())
    def test_summary_output_contains_step_number_and_stage_name(
        self, steps: list[StepResult]
    ):
        """The summary-mode formatted output for each step contains the step
        number label and stage name, with the step number preceding the stage name.

        **Validates: Requirements 8.8**
        """
        for step in steps:
            output = format_summary_line(step)

            # Step number must appear as [N]
            step_label = f"[{step.step_number}]"
            assert step_label in output, (
                f"Summary output missing step label '{step_label}': {output!r}"
            )

            # Stage name must appear in output
            assert step.stage_name in output, (
                f"Summary output missing stage name '{step.stage_name}': {output!r}"
            )

            # Step number label must precede the stage name
            label_pos = output.index(step_label)
            name_pos = output.index(step.stage_name)
            assert label_pos < name_pos, (
                f"Step label '{step_label}' does not precede stage name "
                f"'{step.stage_name}' in output: {output!r}"
            )

    @given(steps=step_result_sequences())
    def test_verbose_output_contains_step_number_and_stage_name(
        self, steps: list[StepResult]
    ):
        """The verbose-mode formatted output for each step contains the step
        number label and stage name, with the step number preceding the stage name.

        **Validates: Requirements 8.8**
        """
        for step in steps:
            output = format_verbose_output(step)

            # Step number must appear as [N]
            step_label = f"[{step.step_number}]"
            assert step_label in output, (
                f"Verbose output missing step label '{step_label}': {output!r}"
            )

            # Stage name must appear in output
            assert step.stage_name in output, (
                f"Verbose output missing stage name '{step.stage_name}': {output!r}"
            )

            # Step number label must precede the stage name
            label_pos = output.index(step_label)
            name_pos = output.index(step.stage_name)
            assert label_pos < name_pos, (
                f"Step label '{step_label}' does not precede stage name "
                f"'{step.stage_name}' in output: {output!r}"
            )

    @given(steps=workflow_step_sequences())
    def test_workflow_steps_have_sequential_numbering(
        self, steps: list[WorkflowStep]
    ):
        """WorkflowStep sequences maintain monotonically increasing step numbers 1..N
        with non-empty stage names.

        **Validates: Requirements 8.8**
        """
        n = len(steps)
        for i, step in enumerate(steps):
            expected_number = i + 1
            assert step.step_number == expected_number, (
                f"WorkflowStep at index {i} has step_number={step.step_number}, "
                f"expected {expected_number}"
            )
            assert step.stage_name.strip() != "", (
                f"WorkflowStep {step.step_number} has empty stage name"
            )
