import re 
import hashlib

def valid_password(password):
    #Verifie si le mot de passe est valide 
    
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$*^&¨%]", password):
        return False
    return True

def password_user():
    #demande à l'utilisateur de choisir un mot de passe 
    password = input("Choisissez un mot de passe: ")
    while not valid_password(password):
        print("Mot de passe invalide")
        print("- Contenir au moins 8 caractères")
        print("- Contenir au moins une lettre majuscule")
        print("- DOit contenir au moins un chiffre")
        print("- DOit contenir au moins un caractères spécial(!,@,#,%,^,&,*)")
        password = input("Veuillez choisir un autre mot de passe: ")
    return password 

def hash_password(password):
    #Crypte le mot de passe que l'utilisateur a entré en utilisant l'algorithme de hachage SHA-256
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    #demande à l'utilisateur de choisri un mot de passe, le vérifie et le crypte en utilisant le programme 
    password = password_user()
    hashed_password = hash_password(password)
    print(f"Mot de passe validé et crypté avec succès. VOici le hachage SHA-256: {hashed_password}")
    
if __name__ == "__main__":
    main()
    
    

