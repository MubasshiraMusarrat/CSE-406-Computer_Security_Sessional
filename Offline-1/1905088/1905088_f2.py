import binascii

def file_to_string(str):
    bin_data = open(str, 'rb').read()
    hex_data = binascii.hexlify(bin_data)
    decoded_string = hex_data.decode("ascii")
    return decoded_string

def string_to_file(plainText, str):
    data = bytes.fromhex(plainText)

    with open(str, 'wb') as file:
        file.write(data)

def main():
    file_input = "apple.jpg"
    raw_text = file_to_string(file_input)
    # print(raw_text)
    string_to_file(raw_text, "apple2.jpg")

if __name__ == "__main__":
    main()