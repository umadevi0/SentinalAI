import pandas as pd
input_file="testing/verified_online.csv"
output_file="testing/output_phish.csv"
df=pd.read_csv(input_file)
df["ClassLabel"]=0
df.to_csv(output_file,index=False)
