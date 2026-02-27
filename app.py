import pandas as pd
import joblib
from URLFeatureExtraction import extract_features  # use your actual file name

# Load trained model
model = joblib.load("best_phishing_model.pkl")

FEATURE_ORDER = [
    'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth',
    'Redirection', 'https_Domain', 'TinyURL', 'Prefix/Suffix',
    'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End',
    'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
]

def predict_url(url):
    feature_dict = extract_features(url)

    input_df = pd.DataFrame([feature_dict])
    input_df = input_df[FEATURE_ORDER]

    prediction = model.predict(input_df)[0]

    if prediction == 1:
        return "⚠️ Phishing Website Detected"
    else:
        return "✅ Legitimate Website"

# Interactive mode
if __name__ == "__main__":
    while True:
        url = input("\nEnter URL (or type 'exit' to quit): ")

        if url.lower() == "exit":
            print("Exiting...")
            break

        result = predict_url(url)
        print("Result:", result)