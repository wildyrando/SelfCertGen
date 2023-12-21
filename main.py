# ----------------------------------------------------------------------------------
#  Name         : SelfCertGen
#  Desc         : Self Certificate Generator
#  Author       : Wildy Sheverando
#  Date         : 03-03-2023
#  Contact      : hai@wildyrando.com
#  License      : GNU General Public License V3
# ----------------------------------------------------------------------------------

# >> Import Requirement
from OpenSSL import *
import re, os

# >> Declare Pattern to use for validate
country_pattern             = "^[A-Z]{2}$"
state_pattern               = "^[a-zA-Z ]+$"
location_pattern            = "^[a-zA-Z ]+$"
commonname_pattern          = "^[a-zA-Z0-9 ]+$"
organization_pattern        = "^[a-zA-Z0-9 ]+$"
organizationunit_pattern    = "^[a-zA-Z0-9 ]+$"
email_pattern               = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
expired_pattern             = "^[0-9]+$"

# >> Function for userinput
def userinput(dtlprompt, pattern, mtdn):
    while True:
        inputs = input(dtlprompt)
        if re.match(pattern, inputs):
            if mtdn == "expired":
                expired = int(inputs)
                if expired > 1000:
                    print("Expired max is 50 years!")
                else:
                    return expired
            else:
                return inputs
        else:
            print(f"Please input a valid {mtdn}")

# >> Function to validating path
def checkpath(dtlprompt):
    while True:
        inputs = input(dtlprompt)
        if os.path.isdir(os.path.dirname(inputs)):
            return inputs
        else:
            print(f"{inputs} not valid directory or not exists")

# >> Function for writefiles
def writefile(filenames, data, pathtosave):
    try:
        pathtosaves = f"{pathtosave}/{filenames}"
        with open(pathtosaves, "wb") as f:
            f.write(data)
        print(f"Success save {filenames} to {pathtosave}")
    except IOError:
        print(f"Cannot save {filenames} to {pathtosave}")

# >> Clear the client window
os.system('cls' if os.name == 'nt' else 'clear')

# >> Input certificate information & path to save the certificate
country              = userinput("Country               : ", country_pattern,           "country"            )
state                = userinput("State                 : ", state_pattern,             "state"              )
location             = userinput("Location              : ", location_pattern,          "location"           )
commonname           = userinput("CommonName            : ", commonname_pattern,        "commonname"         )
organization         = userinput("Organization          : ", organization_pattern,      "organization"       )
organizationunit     = userinput("Organization Unit     : ", organization_pattern,      "organizationunit"   )
email                = userinput("Email                 : ", email_pattern,             "email"              )
expired              = userinput("Expired in (Years)    : ", expired_pattern,           "expired"            )
pathtosave           = checkpath("Directory for result  : ")

# >> Generate key for the certificate in RSA 2048
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

# >> Generate csr for the certificate in key sha256
req = crypto.X509Req()
req.get_subject().C = country
req.get_subject().ST = state
req.get_subject().L = location
req.get_subject().O = organization
req.get_subject().OU = organizationunit
req.get_subject().CN = commonname
req.get_subject().emailAddress = email
req.set_pubkey(key)
req.sign(key, "sha256")

# >> Generate cert
cert = crypto.X509()
cert.get_subject().C = country
cert.get_subject().ST = state
cert.get_subject().L = location
cert.get_subject().O = organization
cert.get_subject().OU = organizationunit
cert.get_subject().CN = commonname
cert.get_subject().emailAddress = email
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(int(expired)*365*24*60*60)  # Valid for 3 years
cert.set_issuer(cert.get_subject())
cert.set_pubkey(key)
cert.sign(key, "sha256")

# >> Writing cert
print(f"\n\nProcess saving into path\n===================================")
ca_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
writefile("ca.cer", ca_data, f"{pathtosave}")
cert_key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
writefile("cert.key", cert_key_data, f"{pathtosave}")
ca_csr_data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
writefile("cert.csr", ca_csr_data, f"{pathtosave}")
fullchain_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
writefile("fullchain.cer", fullchain_data, f"{pathtosave}")
