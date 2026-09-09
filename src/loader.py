import pandas as pd
import numpy as np
from pathlib import Path
from config import dataset_file

def load_features_schema():
    project_root = Path(__file__).resolve().parent.parent
    features = pd.read_csv(project_root / "datasets" / "UNSW-NB15_features.csv",encoding="cp1252")
    numeric_data = []
    string_data = []
    time_data = []
    for index, row in features.iterrows():
        if (row["Type"] == "integer") or (row["Type"] =="float") or (row["Type"] =="binary"):
            numeric_data.append(row['Name'])

        elif row["Type"] == ("nominal"):
            string_data.append(row['Name'])

        elif row["Type"] == ("Timestamp"):
            time_data.append(row['Name'])
    return numeric_data, string_data, time_data

def load_dataset():
    dataframes = []
    for file in dataset_file:
        df = pd.read_csv(file, low_memory=False)
        dataframes.append(df)

    dataset = pd.concat(dataframes, ignore_index=True)
    return dataset

def clean_data(df):
    df.columns = df.columns.str.strip()
    numeric_data, string_data, time_data = load_features_schema()

    for column in numeric_data:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    for column in string_data:
        df[column] = df[column].astype(str).str.strip()

    for column in time_data:
        df[column] = pd.to_datetime(df[column],unit="s",errors="coerce")

    required_columns = ["srcip","dstip","sport","dsport","Label","Stime","Ltime"]

    df.dropna(subset=required_columns, inplace=True)
    df.drop_duplicates(inplace=True)
    return df

def analyze_dataset(df):

    dataset_rows_columns = df.shape
    dataset_types = df.dtypes

    na_values = df.isna().sum()
    duplicate_count = df.duplicated().sum()

    unique_source_ips = df["srcip"].nunique()
    unique_destination_ips = df["dstip"].nunique()
    label_distribution = df["Label"].value_counts()


    df_analyze={'dataset_rows' : dataset_rows_columns[0],
                'dataset_columns' : dataset_rows_columns[1],
                'dataset_types' : dataset_types,
                'NA_values' : na_values,
                'duplicate_count' : duplicate_count,
                'unique_source_ips' : unique_source_ips,
                'unique_destination_ips' : unique_destination_ips,
                'label_distribution' : label_distribution,
                }
    return df_analyze

def detect_suspicious_ips(df,window_minutes=1):
    df["time_window"] = df["Stime"].dt.floor(f"{window_minutes}min")
    time_group =  df.groupby(['time_window', 'srcip'])
    flow_count = time_group.size()
    unique_dstip = time_group["dstip"].nunique()
    unique_dsport =  time_group["dsport"].nunique()
    attack_count = time_group["Label"].sum()
    attack_ratio = attack_count / flow_count
    df = pd.DataFrame()
    df['flow_count'] = flow_count
    df['unique_dstip'] = unique_dstip
    df['unique_dsport'] = unique_dsport
    df['attack_count'] = attack_count
    df['attack_ratio'] = attack_ratio
    df = df.reset_index()

    return df

def get_risk_reasons(row):
    reasons = []

    if row["is_burst_traffic"]:
        reasons.append("High traffic volume")

    if row["is_port_scan"]:
        reasons.append("Multiple destination ports")

    if row["is_network_scan"]:
        reasons.append("Multiple destination IPs")

    if row["is_attack_heavy"]:
        reasons.append("High attack ratio")

    return reasons


def calculate_risk_score(df,threshold=50 ):
    df_copy = df.copy()

    df_copy['is_burst_traffic']= df_copy['flow_count']>=threshold

    port_threshold = 5
    df_copy['is_port_scan']= df_copy['unique_dsport']>=port_threshold

    network_threshold = 50
    df_copy['is_network_scan']= df_copy['unique_dstip']>=network_threshold

    attack_ratio_threshold = 0.7
    df_copy['is_attack_heavy']= df_copy['attack_ratio']>=attack_ratio_threshold

    df_copy['risk_score']=0
    burst_traffic_score= 1
    port_score = 3
    network_score= 2
    attack_score=4
    df_copy['risk_score'] = ((df_copy['is_burst_traffic'] * burst_traffic_score)+
                             (df_copy['is_port_scan'] * port_score)+
                             (df_copy['is_network_scan'] * network_score)+
                             (df_copy['is_attack_heavy'] * attack_score))


    df_copy['risk_level'] = np.select(
    [(df_copy['risk_score'] >= 1) & (df_copy['risk_score'] <= 2),
            (df_copy['risk_score'] >= 3) & (df_copy['risk_score'] <= 5),
            (df_copy['risk_score'] >= 6)],
        ['Low','Medium','High'],
        default='Normal')

    df_copy["risk_reasons"] = df_copy.apply(get_risk_reasons, axis=1)

    return df_copy


def generate_security_report(df):
    df_copy = calculate_risk_score(df)
    high_risk_ips = df_copy[df_copy["risk_level"] == "High"]
    medium_risk_ips = df_copy[df_copy["risk_level"] == "Medium"]
    low_risk_ips = df_copy[df_copy["risk_level"] == "Low"]
    high_risk_count = len(high_risk_ips)
    medium_risk_count = len(medium_risk_ips)
    low_risk_count = len(low_risk_ips)
    normal_count = len(df_copy[df_copy["risk_level"] == "Normal"])
    total_suspicious_ips= df_copy.shape[0]
    average_risk_score= df_copy["risk_score"].mean()
    max_risk_score = df_copy["risk_score"].max()
    high_risk_ip_list = "\n".join(high_risk_ips["srcip"].astype(str))
    top_risk_ips = df_copy.sort_values(by=['risk_score'], ascending=False).head()
    top_risk_text = "\n".join(f"{row.srcip} (Score: {row.risk_score})"for _, row in top_risk_ips.iterrows() )

    security_report = f"""
    Security Report

    Total Suspicious IPs: {total_suspicious_ips}

    Risk Levels

    High: {high_risk_count}
    Medium: {medium_risk_count}
    Low: {low_risk_count}
    Normal: {normal_count}

    Average Risk Score: {average_risk_score}
    Maximum Risk Score: {max_risk_score}

    High Risk IPs

    {high_risk_ip_list}

    Top 5 Highest Risk IPs

    {top_risk_text}
    """

    return security_report




