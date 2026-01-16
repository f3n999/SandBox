# 🤝 Guide de Contribution

Merci de contribuer au projet **Défense Anti-Ransomware** ! 🎉

## 📋 Table des matières

- [Code de conduite](#code-de-conduite)
- [Comment contribuer](#comment-contribuer)
- [Workflow Git](#workflow-git)
- [Standards de code](#standards-de-code)
- [Tests](#tests)
- [Pull Requests](#pull-requests)

---

## 🎯 Code de conduite

- ✅ Soyez respectueux et professionnel
- ✅ Acceptez les critiques constructives
- ✅ Focalisez sur l'objectif commun
- ❌ Pas de discrimination
- ❌ Pas de spam ou trolling

---

## 💡 Comment contribuer

### Rapporter un bug

1. Vérifiez qu'il n'existe pas déjà dans [Issues](https://github.com/f3n999/SandBox/issues)
2. Créez une nouvelle issue avec le template "Bug Report"
3. Incluez :
   - Description claire du bug
   - Étapes pour reproduire
   - Comportement attendu vs actuel
   - Screenshots si applicable
   - Version des outils (Python, Docker, etc.)

### Proposer une fonctionnalité

1. Créez une issue avec le template "Feature Request"
2. Expliquez :
   - Le problème que ça résout
   - La solution proposée
   - Des alternatives envisagées

### Corriger un bug ou ajouter une feature

1. Assignez-vous l'issue correspondante
2. Suivez le [Workflow Git](#workflow-git)
3. Créez une Pull Request

---

## 🔀 Workflow Git

### 1. Fork & Clone

```bash
# Fork le repo sur GitHub
# Puis clone ton fork
git clone https://github.com/TON-USERNAME/SandBox.git
cd SandBox

# Ajoute le repo original comme remote
git remote add upstream https://github.com/f3n999/SandBox.git
```

### 2. Créer une branche

```bash
# Toujours partir de main à jour
git checkout main
git pull upstream main

# Créer une branche feature
git checkout -b feature/nom-de-ta-feature

# Ou pour un fix
git checkout -b fix/nom-du-bug
```

### 3. Convention de nommage des branches

- `feature/nom-feature` : nouvelle fonctionnalité
- `fix/nom-bug` : correction de bug
- `docs/sujet` : documentation
- `test/sujet` : ajout de tests
- `refactor/sujet` : refactoring

### 4. Commits

```bash
# Format de commit
git commit -m "type(scope): description courte"

# Exemples
git commit -m "feat(orchestrator): add SHA256 hashing logic"
git commit -m "fix(cape): resolve API timeout issue"
git commit -m "docs(readme): update installation steps"
git commit -m "test(orchestrator): add unit tests for heuristic"
```

**Types de commits :**
- `feat`: nouvelle fonctionnalité
- `fix`: correction de bug
- `docs`: documentation
- `test`: tests
- `refactor`: refactoring
- `style`: formatage code
- `chore`: maintenance

### 5. Push & Pull Request

```bash
# Push ta branche
git push origin feature/nom-de-ta-feature

# Ensuite, crée une Pull Request sur GitHub
```

---

## 🎨 Standards de code

### Python (PEP 8)

```python
# Imports
import os
import sys
from typing import List, Dict

# Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

# Functions with type hints
def analyze_file(file_path: str, threshold: float = 0.75) -> Dict[str, any]:
    """
    Analyse un fichier suspect.

    Args:
        file_path: Chemin vers le fichier
        threshold: Seuil de détection (0-1)

    Returns:
        Dict contenant le verdict et métadonnées
    """
    pass

# Classes
class FileAnalyzer:
    """Analyseur de fichiers suspects."""

    def __init__(self, config: Dict):
        self.config = config
```

### Formatage

```bash
# Black (auto-formatage)
black orchestrator/

# Flake8 (linter)
flake8 orchestrator/ --max-line-length=100

# isort (tri imports)
isort orchestrator/
```

### Docker

- Utilisez des images officielles quand possible
- Multi-stage builds pour réduire la taille
- `.dockerignore` pour exclure fichiers inutiles
- Commentaires clairs dans Dockerfile

### Documentation

- Docstrings pour toutes les fonctions/classes
- README à jour
- Commentaires pour code complexe
- Architecture diagram si changements majeurs

---

## 🧪 Tests

### Exécuter les tests

```bash
# Tous les tests
pytest

# Tests unitaires seulement
pytest tests/unit/

# Tests avec coverage
pytest --cov=orchestrator tests/

# Tests spécifiques
pytest tests/unit/test_hashing.py::test_sha256_hash
```

### Écrire des tests

```python
# tests/unit/test_hashing.py
import pytest
from orchestrator.core.hashing import calculate_sha256

def test_sha256_hash():
    """Test calcul SHA256."""
    data = b"test data"
    expected = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    assert calculate_sha256(data) == expected

def test_sha256_empty():
    """Test SHA256 avec données vides."""
    with pytest.raises(ValueError):
        calculate_sha256(b"")
```

**Couverture minimale** : 80%

---

## 🔍 Pull Requests

### Checklist avant PR

- [ ] Code fonctionne localement
- [ ] Tests passent (`pytest`)
- [ ] Code formaté (`black`, `flake8`)
- [ ] Documentation à jour
- [ ] Commits propres et clairs
- [ ] Branche à jour avec `main`

### Template PR

```markdown
## Description
[Décris tes changements]

## Type de changement
- [ ] Bug fix
- [ ] Nouvelle fonctionnalité
- [ ] Breaking change
- [ ] Documentation

## Tests
- [ ] Tests unitaires ajoutés
- [ ] Tests intégration ajoutés
- [ ] Tests manuels effectués

## Screenshots (si applicable)
[Ajoute des captures d'écran]

## Checklist
- [ ] Code respecte les standards
- [ ] Documentation mise à jour
- [ ] Tests passent
```

### Review process

1. **Création PR** : Un reviewer est assigné automatiquement
2. **Review** : Le reviewer commente / approuve / demande changements
3. **Corrections** : Tu appliques les changements demandés
4. **Merge** : Une fois approuvé, le maintainer merge

---

## 🚀 Release process

### Versioning (Semantic Versioning)

- **MAJOR** : Changements incompatibles (breaking changes)
- **MINOR** : Nouvelles fonctionnalités (rétrocompatibles)
- **PATCH** : Corrections de bugs

Exemple : `v1.2.3`

### Créer une release

```bash
# Tag la version
git tag -a v1.0.0 -m "Release v1.0.0: Initial production release"
git push origin v1.0.0

# GitHub Actions créera automatiquement la release
```

---

## 📞 Questions ?

- **Issues** : [GitHub Issues](https://github.com/f3n999/SandBox/issues)
- **Discussions** : [GitHub Discussions](https://github.com/f3n999/SandBox/discussions)
- **Email équipe** : oteria-b3-ransomware@example.com

---

**Merci de contribuer ! 🙏**

*Made with ❤️ by Oteria B3 Team*
