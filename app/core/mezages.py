from bootkit.mezage import Mezage


mzg_money = Mezage(code="money", text="Must match the money format")

mzg_null_or_money = Mezage(code="null_or_money", text="Must be null or match the money format")

mzg_opt_null_or_money = Mezage(code="opt_null_or_money", text="Optional, otherwise must be null or match the money format")
