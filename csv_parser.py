# ******************************************************************************
# csv_parser.py
#
# Date      Name       Description
# ========  =========  ========================================================
# 6/11/19   Paudel     Initial version,
# ******************************************************************************

import pandas as pd

class CsvParser:

    def __init__(self):
        print("\n\n..... Parsing CSV File.....")
        pass

    def read_csv_file(self, filename):
        data = pd.read_csv(filename)
        print("data: ", data.head())

