import pandas as pd
input_file="testing//tranco_ZJQGG-1m.csv/top-1m.csv"
output_file="testing/output_traco.csv"
df=pd.read_csv(input_file,header=None)
df=df.iloc[:,-1]
output_df=pd.DataFrame({
    "url":df,
    "ClassLabel":1.0
})
output_df.to_csv(output_file,index=False)
