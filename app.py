# app.py
"""
Fake / Hardcoded Streamlit demo app for:
AI-Based Cyber Threat Predictor (UNSW-NB15 demo)
- This app uses a deterministic rule-based "fake model" to demonstrate UI,
  predictions, explainability bars, and sample alerts.
- Replace `predict_rule_based()` with a real model.predict() later.
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import io
from datetime import datetime, timedelta

np.random.seed(42)
sns.set_style("whitegrid")


# ---------------------------
# Utility & Fake model logic
# ---------------------------
def predict_rule_based(sample_df: pd.DataFrame):
    """
    A deterministic, explainable rule-based "fake model".
    Returns:
      probs: numpy array of shape (n, 2) -> [prob_normal, prob_attack]
      preds: numpy array of ints (0 normal, 1 attack)
      contributions: list of dicts (per-row feature contributions)
    The rules are simple heuristics combining a few features.
    """
    probs = []
    preds = []
    contributions = []
    for _, row in sample_df.iterrows():
        # Score composition (higher => more likely attack)
        score = 0.0
        contrib = {}
        # Example heuristics (made-up, for demo only)
        # 1) extremely high bytes transferred
        sbytes = float(row.get("sbytes", 0))
        dbytes = float(row.get("dbytes", 0))
        rate = float(row.get("rate", 0))
        spkts = float(row.get("spkts", 0))
        dpkts = float(row.get("dpkts", 0))

        # contribution rules
        contrib["sbytes"] = 0.0
        if sbytes > 1e6:
            contrib["sbytes"] = 0.45
        elif sbytes > 1e5:
            contrib["sbytes"] = 0.2
        else:
            contrib["sbytes"] = 0.0

        contrib["dbytes"] = 0.0
        if dbytes > 1e6:
            contrib["dbytes"] = 0.25
        elif dbytes > 1e5:
            contrib["dbytes"] = 0.1

        contrib["rate"] = 0.0
        if rate > 100000:
            contrib["rate"] = 0.15
        elif rate > 10000:
            contrib["rate"] = 0.05

        contrib["pkts_imbalance"] = 0.0
        if spkts > (dpkts * 5 + 50):
            contrib["pkts_imbalance"] = 0.15
        elif dpkts > (spkts * 5 + 50):
            contrib["pkts_imbalance"] = 0.1

        # total score (clamped)
        score = sum(contrib.values())
        score = min(score, 0.99)

        # probability attack = score + small noise based on protocol/features
        base_attack_prob = score
        # tiny randomization for variety
        attack_prob = float(np.round(base_attack_prob + (np.random.rand() * 0.03), 3))
        attack_prob = min(max(attack_prob, 0.001), 0.999)

        probs.append([1 - attack_prob, attack_prob])
        preds.append(int(attack_prob > 0.5))
        contributions.append(contrib)

    return np.array(probs), np.array(preds), contributions


def generate_sample_alerts(n=8):
    """Return a fake alert timeline DataFrame for dashboard."""
    now = datetime.now()
    rows = []
    attack_types = ["DoS", "Exploitation", "Fuzzers", "Reconnaissance", "Backdoor", "Shellcode"]
    for i in range(n):
        rows.append({
            "timestamp": (now - timedelta(minutes=10 * i)).strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": f"192.168.1.{np.random.randint(2,250)}",
            "dst_ip": f"10.0.0.{np.random.randint(2,250)}",
            "attack_type": np.random.choice(attack_types, p=[0.25,0.2,0.15,0.2,0.1,0.1]),
            "alert_score": float(round(np.random.uniform(0.6, 0.98), 2))
        })
    return pd.DataFrame(rows)


# ---------------------------
# UI
# ---------------------------

st.set_page_config(page_title="AI Cyber Threat Predictor (Demo)", layout="wide", initial_sidebar_state="expanded")

# header
st.markdown("<h1 style='text-align:center'>AI-Based Cyber Threat Predictor</h1>", unsafe_allow_html=True)


# sidebar: quick controls
with st.sidebar:
    st.header("Demo Controls")
    mode = st.radio("Input mode", ["Single sample", "Upload CSV (batch)"], index=0)
    st.markdown("---")
    st.markdown("**Model**: Hardcoded rule-based predictor (demo only)")
    st.markdown("Tip: Use 'Upload CSV' to test multiple rows (columns: sbytes,dbytes,rate,spkts,dpkts,proto,service,state)")

# layout columns
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Input")
    if mode == "Single sample":
        # Example fields
        c1, c2, c3 = st.columns(3)
        with c1:
            sbytes = st.number_input("sbytes (source bytes)", min_value=0, value=5000, step=1000)
            dbytes = st.number_input("dbytes (dest bytes)", min_value=0, value=0, step=1000)
        with c2:
            rate = st.number_input("rate (bytes/sec)", min_value=0.0, value=125000.0, step=1000.0)
            spkts = st.number_input("spkts (source packets)", min_value=0, value=25, step=1)
        with c3:
            dpkts = st.number_input("dpkts (dest packets)", min_value=0, value=1, step=1)
            proto = st.selectbox("proto", ["tcp", "udp", "icmp", "other"], index=0)
        # build dataframe row
        sample = pd.DataFrame([{
            "sbytes": sbytes, "dbytes": dbytes, "rate": rate,
            "spkts": spkts, "dpkts": dpkts,
            "proto": proto
        }])
        st.markdown("**Sample preview:**")
        st.dataframe(sample)
    else:
        uploaded = st.file_uploader("Upload CSV file", type=["csv"])
        if uploaded is not None:
            sample = pd.read_csv(uploaded)
            st.write("Preview (first 10 rows):")
            st.dataframe(sample.head(10))
        else:
            st.info("Upload a CSV with columns: sbytes,dbytes,rate,spkts,dpkts,...")
            sample = None

    st.markdown("---")
    run = st.button("Run Prediction")

with col2:

    # create sample CSV to download
    sample_csv_df = pd.DataFrame({
        "sbytes": [5000, 2000000, 100, 123456],
        "dbytes": [0, 800000, 10, 0],
        "rate": [125000.0, 250000.0, 500.0, 50000.0],
        "spkts": [25, 4000, 3, 200],
        "dpkts": [1, 3000, 1, 10],
        "proto": ["udp", "tcp", "icmp", "tcp"]
    })
    csv_buf = io.StringIO()
    sample_csv_df.to_csv(csv_buf, index=False)
    st.download_button("Download sample CSV", csv_buf.getvalue(), file_name="demo_sample.csv", mime="text/csv")
    st.markdown("---")
    st.subheader("Recent Alerts (demo)")
    alerts = generate_sample_alerts(6)
    st.table(alerts)

# ---------------------------
# Prediction & Results Panel
# ---------------------------
st.markdown("---")
st.subheader("Prediction Output")

if run:
    if sample is None:
        st.error("No input data available. Provide a sample or upload a CSV.")
    else:
        probs, preds, contribs = predict_rule_based(sample)
        # attach to dataframe
        pred_df = sample.copy().reset_index(drop=True)
        pred_df["prob_normal"] = probs[:, 0]
        pred_df["prob_attack"] = probs[:, 1]
        pred_df["pred_label"] = preds
        pred_df["label_text"] = pred_df["pred_label"].map({0: "Normal", 1: "Attack"})

        # show predictions
        st.markdown("### Results")
        st.dataframe(pred_df.style.format({
            "prob_normal": "{:.3f}",
            "prob_attack": "{:.3f}"
        }))

        # Summary metrics (demo)
        avg_attack_prob = pred_df["prob_attack"].mean()
        attack_pct = 100 * pred_df["pred_label"].mean()
        st.markdown(f"**Detected attack percentage (rows predicted as Attack):** {attack_pct:.1f}%")
        st.markdown(f"**Average attack probability:** {avg_attack_prob:.3f}")

        # bar chart of prediction probabilities
        fig, ax = plt.subplots(figsize=(6, 3))
        ax = sns.barplot(x=pred_df.index, y=pred_df["prob_attack"])
        ax.set_ylabel("Attack Probability")
        ax.set_xlabel("Sample index")
        ax.set_ylim(0, 1)
        st.pyplot(fig)

        # Explainability: show contribution bars for the first sample only (or mean)
        st.markdown("### Explainability (Feature Contributions)")
        # aggregate contribution keys
        keys = sorted({k for d in contribs for k in d.keys()})
        mean_contrib = {k: np.mean([d.get(k, 0.0) for d in contribs]) for k in keys}

        # plot contributions
        fig2, ax2 = plt.subplots(figsize=(6, 3))
        ax2.barh(list(mean_contrib.keys()), list(mean_contrib.values()), color="salmon")
        ax2.set_xlabel("Contribution (relative, demo)")
        ax2.set_xlim(0, 0.6)
        st.pyplot(fig2)

        # show a fake confusion matrix when batch size >1 (demo)
        if len(pred_df) > 1:
            st.markdown("### Demo Confusion Matrix (simulated)")
            # build fake confusion matrix
            # use some heuristic: assume majority normal, some attacks
            tn = int((len(pred_df) - pred_df["pred_label"].sum()) * 0.95)
            fp = int((len(pred_df) - pred_df["pred_label"].sum()) * 0.05)
            fn = int(pred_df["pred_label"].sum() * 0.1)
            tp = int(pred_df["pred_label"].sum() * 0.9)
            cm = pd.DataFrame([[tn, fp], [fn, tp]], index=["Actual Normal","Actual Attack"], columns=["Pred Normal","Pred Attack"])
            st.table(cm)

        st.success("Demo prediction complete — replace the rule-based function with your model.predict for real inference.")

else:
    st.info("Configure inputs in the left panel then click **Run Prediction**.")

# ---------------------------
# Footer / notes
# ---------------------------
st.markdown("---")
