import pandas as pd

# Load PhishTank malicious URLs
df_phish = pd.read_csv("raw_datasets/malicious-urls.csv")
df_phish = df_phish[["url"]].drop_duplicates()
df_phish["label"] = 1  # malicious

# Load Tranco domains and convert to URLs
df_tranco = pd.read_csv("raw_datasets/benign-urls.csv", header=None, names=["rank", "domain"])
df_tranco["url"] = "http://" + df_tranco["domain"]
df_tranco = df_tranco[["url"]].drop_duplicates()
df_tranco["label"] = 0  # benign

# Sample to match size of malicious dataset
df_tranco_sampled = df_tranco.sample(n=len(df_phish), random_state=42)

# Combine and shuffle
df_combined = pd.concat([df_phish, df_tranco_sampled], ignore_index=True)
df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

# Save it
df_combined.to_csv("url_dataset_balanced.csv", index=False)
print("✅ Combined and saved:", len(df_combined), "entries")
