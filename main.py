import torch
import torch.nn as nn

m = nn.GLU()
input = torch.randn(4, 2)
output = m(input)
print(input, output)