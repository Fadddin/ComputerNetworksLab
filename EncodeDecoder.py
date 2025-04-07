a = input("Enter Input : ")
print(ord(a))
b = int(input("Enter ASCII : " ))
print(chr(b))

# def getASCII(char) :

#     # A
#     if(len(char) != 1):
#         raise ValueError("Input must be a single character")
    
#     asciiDict = {chr(i) : i for i in range(128)}

#     ## $ : 1
#     ## 65 : A

#     if char in asciiDict:
#         return asciiDict[char]
#     else:
#         return ValueError("Character not in the range of ASCII characters")

# def getChar(code):

#     if not (0 <= code < 128):
#         raise ValueError("Must be in range")
    
#     asciiDict = {i : chr(i) for i in range(128)}

#     ## 1 : $
#     ## 65 : A

#     if(code in asciiDict):
#             return asciiDict[code]
#     else:
#         return ValueError("ASCII code not in the range of ASCII characters")
    
    
# def main():
#      a = input("Enter a character: ")
#      print(getASCII(a))
#      b = int(input("Enter ASCII code : "))
#     #  print(getChar(b))
#      print(chr(b))

# if __name__ == "__main__":
#      main()