import torch
import torch.nn as nn

from ml_engine.world_model.state_representation import STATE_DIM


class NetworkStateTransitionModel(nn.Module):
    def __init__(
        self,
        state_dim: int = STATE_DIM,
        hidden_size: int = 64,
        num_layers: int = 2
    ):
        super().__init__()

        self.state_dim = state_dim
        self.hidden_size = hidden_size
        self.num_layers = num_layers

        self.lstm = nn.LSTM(
            input_size=state_dim,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0.0
        )

        self.state_head = nn.Linear(
            hidden_size,
            state_dim
        )

        self.risk_head = nn.Linear(
            hidden_size,
            1
        )

    def forward(self, x, k_steps: int = 1, return_risk_logits: bool = False):
        _, (h, c) = self.lstm(x)

        predicted_states = []
        risk_scores = []
        risk_logits = []

        last_input = x[:, -1, :]

        for _ in range(k_steps):
            output, (h, c) = self.lstm(
                last_input.unsqueeze(1),
                (h, c)
            )

            hidden_state = output[:, -1, :]

            next_state = torch.sigmoid(
                self.state_head(hidden_state)
            )

            risk_logit = self.risk_head(hidden_state)
            risk = torch.sigmoid(risk_logit)

            predicted_states.append(next_state)
            risk_scores.append(risk)
            risk_logits.append(risk_logit)

            last_input = next_state

        predicted_states = torch.stack(
            predicted_states,
            dim=1
        )

        risk_scores = torch.stack(
            risk_scores,
            dim=1
        )

        if return_risk_logits:
            return (
                predicted_states,
                risk_scores,
                torch.stack(risk_logits, dim=1),
            )

        return predicted_states, risk_scores


def rollout_k_steps(
    model: NetworkStateTransitionModel,
    initial_window,
    k: int = 5,
    return_risk_logits: bool = False
):
    model.eval()

    if not isinstance(initial_window, torch.Tensor):
        initial_window = torch.tensor(
            initial_window,
            dtype=torch.float32
        )

    if initial_window.dim() == 2:
        initial_window = initial_window.unsqueeze(0)
    if initial_window.dim() != 3 or initial_window.shape[-1] != model.state_dim:
        raise ValueError(
            f"Rollout input must have shape (batch, time, {model.state_dim}), "
            f"received {tuple(initial_window.shape)}"
        )

    device = next(model.parameters()).device

    initial_window = initial_window.to(device)

    with torch.no_grad():
        outputs = model(
            initial_window,
            k_steps=k,
            return_risk_logits=return_risk_logits
        )

        states, risks = outputs[:2]

    result = (
        states.squeeze(0).cpu().numpy(),
        risks.squeeze(0).squeeze(-1).cpu().numpy()
    )
    if return_risk_logits:
        result += (outputs[2].squeeze(0).squeeze(-1).cpu().numpy(),)
    return result