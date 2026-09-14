import torch
import torch.nn as nn


class ThreatForecastLSTM(nn.Module):
    """
    LSTM-based sequence-to-sequence forecaster.
    Takes a historical window of shape (batch, seq_len, num_features)
    and predicts a threat-level scalar for each of `horizon` future steps.
    """

    def __init__(
        self,
        num_features: int = 1,
        hidden_size: int = 64,
        num_layers: int = 2,
        dropout: float = 0.2,
        max_horizon: int = 168,
    ):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.max_horizon = max_horizon

        self.lstm = nn.LSTM(
            input_size=num_features,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )

        # Decoder: takes the final hidden state and autoregressively
        # projects forward one step at a time.
        self.output_proj = nn.Linear(hidden_size, 1)
        self.decoder_cell = nn.LSTMCell(1, hidden_size)

        self.activation = nn.Sigmoid()  # threat level bounded to [0, 1]

    def forward(self, x: torch.Tensor, horizon: int | None = None) -> torch.Tensor:
        """
        x: (batch, seq_len, num_features)
        Returns: (batch, horizon) predicted threat levels in [0, 1]
        """
        horizon = horizon or self.max_horizon
        batch_size = x.size(0)

        _, (h_n, c_n) = self.lstm(x)

        # Use the last layer's hidden/cell state to seed the decoder
        h = h_n[-1]  # (batch, hidden_size)
        c = c_n[-1]

        last_value = self.activation(self.output_proj(h))  # (batch, 1) seed input

        outputs = []
        decoder_input = last_value
        for _ in range(horizon):
            h, c = self.decoder_cell(decoder_input, (h, c))
            step_out = self.activation(self.output_proj(h))  # (batch, 1)
            outputs.append(step_out)
            decoder_input = step_out

        return torch.cat(outputs, dim=1)  # (batch, horizon)


def build_model(num_features: int = 1, **kwargs) -> ThreatForecastLSTM:
    return ThreatForecastLSTM(num_features=num_features, **kwargs)