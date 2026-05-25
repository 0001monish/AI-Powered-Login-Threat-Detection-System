import pandas as pd
from sklearn.ensemble import IsolationForest

# Simple training dataset
training_data = pd.DataFrame([
    [0,0,0,0],
    [0,0,0,0],
    [0,0,0,0],
    [0,0,0,1],
    [0,1,0,0],
],
columns=[
    "new_device",
    "new_country",
    "vpn_detected",
    "failed_login"
])

model = IsolationForest(
    contamination=0.2,
    random_state=42
)

model.fit(training_data)


def predict_anomaly(
    new_device,
    new_country,
    vpn_detected,
    failed_login
):

    sample = pd.DataFrame([
        [
            new_device,
            new_country,
            vpn_detected,
            failed_login
        ]
    ],
    columns=[
        "new_device",
        "new_country",
        "vpn_detected",
        "failed_login"
    ])

    prediction = model.predict(sample)

    return prediction[0]