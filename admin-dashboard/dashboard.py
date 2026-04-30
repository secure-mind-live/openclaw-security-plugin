import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import time

API = "http://localhost:8000/dashboard"

st.set_page_config(page_title="AI Security Monitor", layout="wide")

st.title("🛡️ AI Agent Security Dashboard")

placeholder = st.empty()

while True:

    try:
        r = requests.get(API).json()

        stats = r["stats"]
        events = r["recent_events"]

        df = pd.json_normalize(events)

        with placeholder.container():

            col1, col2, col3, col4 = st.columns(4)

            col1.metric("Total Events", stats["total_events"])
            col2.metric("Prompt Attacks", stats["prompt_attacks"])
            col3.metric("Secret Access", stats["secret_access"])
            col4.metric("Exfiltration", stats["exfiltration"])

            st.divider()

            if not df.empty:

                st.subheader("Attack Categories")

                if "attack.category" in df.columns:

                    attack_counts = df["attack.category"].value_counts()

                    fig = px.pie(
                        values=attack_counts.values,
                        names=attack_counts.index,
                        title="Attack Distribution",
                    )

                    st.plotly_chart(fig, use_container_width=True)

                st.subheader("Recent Events")

                st.dataframe(df)

            else:
                st.write("No events yet")

    except:
        st.write("Waiting for security engine...")

    time.sleep(2)
