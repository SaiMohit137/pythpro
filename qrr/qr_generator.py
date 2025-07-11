import qrcode
from PIL import Image

def main():
    data = input("Enter the data to encode in the QR code: ")
    qr = qrcode.QRCode()
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    pil_img = img.get_image()
    pil_img.save("qrcode.png")
    print("QR code saved as qrcode.png")

if __name__ == "__main__":
    main() 