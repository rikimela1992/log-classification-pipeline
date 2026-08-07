"""Local-only Gradio UI using the same fail-closed application services."""

from __future__ import annotations

from pathlib import Path

from .application import classify_file_preview, classify_message
from .batch import Predictor


def build_demo(predictor: Predictor):
    """Build the interface without launching or exposing a network service."""

    try:
        import gradio as gr
    except ImportError as exc:
        raise RuntimeError(
            "the UI is optional; install 'log-classification-pipeline[ui]'"
        ) from exc

    def classify_one(message: str):
        return classify_message(message, predictor)

    def classify_upload(uploaded_path: str | None):
        if not uploaded_path:
            raise gr.Error("Choose a synthetic JSONL file first.")
        summary, preview = classify_file_preview(
            Path(uploaded_path),
            predictor,
        )
        return summary, preview

    with gr.Blocks(title="Log Classification Pipeline — alpha") as demo:
        gr.Markdown(
            "# Log Classification Pipeline\n"
            "**Alpha demo — not production-ready.** Runs locally and returns "
            "privacy-minimal predictions without echoing input messages."
        )
        with gr.Tab("Single synthetic event"):
            message = gr.Textbox(
                label="Synthetic log message",
                lines=4,
                placeholder="Example: Backup completed successfully",
            )
            classify_button = gr.Button("Classify", variant="primary")
            prediction = gr.JSON(label="Prediction")
            classify_button.click(
                classify_one,
                inputs=message,
                outputs=prediction,
                concurrency_limit=1,
            )

        with gr.Tab("Synthetic JSONL batch"):
            upload = gr.File(
                label="JSONL input",
                file_types=[".jsonl"],
                type="filepath",
            )
            batch_button = gr.Button("Validate and classify")
            summary = gr.JSON(label="Batch summary")
            preview = gr.JSON(label="Prediction preview (first 20)")
            batch_button.click(
                classify_upload,
                inputs=upload,
                outputs=[summary, preview],
                concurrency_limit=1,
            )

        gr.Markdown(
            "The default rules adapter is only a deterministic wiring "
            "baseline. Model downloads are disabled unless explicitly enabled."
        )
    return demo
