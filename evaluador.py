import math
import re

class EvaluadorContrasenas:
    """
    Clase para evaluar la fortaleza de contraseñas
    """
    def __init__(self, intentos_por_segundo=10_000_000_000):
        self.intentos_por_segundo = intentos_por_segundo
        self.contrasenas_comunes = [
            'password', '123456', 'qwerty', 'abc123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', '12345678',
            'password1', 'iloveyou', 'princess', 'starwars'
        ]

    def calcular_entropia(self, contrasena):
        """
        Calcula la entropia (bits de aleatoriedad) de la contraseña
        """
        conjunto_caracteres = 0

        if any(c.islower() for c in contrasena):
            conjunto_caracteres += 26
        if any(c.isupper() for c in contrasena):
            conjunto_caracteres += 26
        if any(c.isdigit() for c in contrasena):
            conjunto_caracteres += 10
        if any(c in "!@#$%+^&*()_+-=[]{}|;:,.<>?" for c in contrasena):
            conjunto_caracteres += 23

        if conjunto_caracteres == 0:
            return 0
        
        entropia = len(contrasena) * math.log2(conjunto_caracteres)
        return entropia
    
    def calcular_tiempo_hackeo(self, entropia):
        """
        Calcula el tiempo estimado para descifrar la contraseña
        """
        combinaciones = 2 ** entropia
        segundos = combinaciones / self.intentos_por_segundo
        
        if segundos < 60:
            return f"{segundos:.2f} segundos"
        elif segundos < 3600:
            return f"{segundos/60:.2f} minutos"
        elif segundos < 86400:
            return f"{segundos/3600:.2f} horas"
        elif segundos < 31536000:
            return f"{segundos/86400:.2f} dias"
        elif segundos < 31536000 * 1000:
            return f"{segundos/31536000:.2f} años"
        elif segundos < 31536000 * 1_000_000:
            return f"{segundos/(31536000*1000):.2f} mil años"
        elif segundos < 31536000 * 1_000_000_000:
            return f"{segundos/(31536000*1_000_000):.2f} millones de años"
        else:
            return f"{segundos/(31536000*1_000_000_000):.2e} miles de millones de años"
    
    def detectar_patrones(self, contraseña):
        """
        Detecta patrones débiles en la contraseña
        """
        problemas = []
        
        if contraseña.lower() in self.contraseñas_comunes:
            problemas.append("Es una contraseña muy común")
        
        if re.search(r'(012|123|234|345|456|567|678|789|890)', contraseña):
            problemas.append("Contiene secuencias numéricas")
        
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)', contraseña.lower()):
            problemas.append("Contiene secuencias alfabéticas")
        
        if re.search(r'(.)\1{2,}', contraseña):
            problemas.append("Tiene caracteres repetidos consecutivamente")
        
        if len(contraseña) < 8:
            problemas.append("Contraseña demasiado corta (mínimo 8 caracteres)")
        
        return problemas
    
    def clasificar_seguridad(self, entropia):
        """
        Clasifica el nivel de seguridad según la entropía
        """
        if entropia < 28:
            return {'nivel': 'PRECARIA', 'puntuacion': 1}
        elif entropia < 36:
            return {'nivel': 'DEBIL', 'puntuacion': 2}
        elif entropia < 60:
            return {'nivel': 'MODERADA', 'puntuacion': 3}
        elif entropia < 80:
            return {'nivel': 'SEGURA', 'puntuacion': 4}
        else:
            return {'nivel': 'MUY SEGURA', 'puntuacion': 5}
    
    def evaluar(self, contraseña):
        """
        Evalúa completamente una contraseña
        """
        if len(contraseña) == 0:
            return {
                'nivel': 'Sin contraseña',
                'puntuacion': 0,
                'entropia': 0,
                'tiempo_hackeo': '0 segundos',
                'problemas': ['No hay contraseña para evaluar'],
                'longitud': 0
            }
        
        entropia = self.calcular_entropia(contraseña)
        tiempo_hackeo = self.calcular_tiempo_hackeo(entropia)
        problemas = self.detectar_patrones(contraseña)
        clasificacion = self.clasificar_seguridad(entropia)
        
        return {
            'nivel': clasificacion['nivel'],
            'puntuacion': clasificacion['puntuacion'],
            'entropia': entropia,
            'tiempo_hackeo': tiempo_hackeo,
            'problemas': problemas,
            'longitud': len(contraseña)
        }