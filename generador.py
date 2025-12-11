import random
import string

class GeneradorContrasenas:
    """
    Clase para generar contraseñas aleatorias seguras
    """

    def __init__(self):
        self.minusculas = string.ascii_lowercase
        self.mayusculas = string.ascii_uppercase
        self.numeros = string.digits
        self.simbolos = "!@##%^&()_+-=[]{}|;:,.<>?"

    def generar(self, longitud=16, usar_mayusculas=True, usar_minusculas=True,
                usar_numeros=True, usar_simbolos=True):
        """
        Genera una contraseña aleatoria
        """

        caracteres = ""

        if usar_minusculas:
            caracteres += self.minusculas
        if usar_mayusculas:
            caracteres += self.mayusculas
        if usar_numeros:
            caracteres += self.numeros
        if usar_simbolos:
            caracteres += self.simbolos
        
        if not caracteres:
            raise ValueError("Debes seleccionar al menos un tipo de caracter")
        
        contrasena = ''.join(random.choice(caracteres) for _ in range(longitud))
        return contrasena
    
    def generar_multiple(self, cantidad=5, longitud=16, **kwargs):
        """
        Genera multiples contraseñas
        """
        return {self.generar(longitud, **kwargs) for _ in range(cantidad)}