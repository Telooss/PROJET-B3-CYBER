# Contributing to HTTP Honeypot (Telosmiligramme)

Merci de votre intérêt pour contribuer à ce projet ! Voici comment vous pouvez nous aider.

## 🤝 Comment contribuer

### Rapporter des bugs

1. Vérifiez que le bug n'a pas déjà été rapporté dans les [Issues](../../issues)
2. Créez une nouvelle issue avec le template de bug report
3. Incluez :
   - Description détaillée du problème
   - Étapes pour reproduire
   - Comportement attendu vs obtenu
   - Logs pertinents
   - Environnement (OS, version Docker, etc.)

### Proposer des améliorations

1. Créez une issue avec le template de feature request
2. Décrivez clairement :
   - Le problème que cela résoudrait
   - La solution proposée
   - Les alternatives considérées

### Contribuer au code

1. **Fork** le repository
2. **Créez** une branche pour votre fonctionnalité (`git checkout -b feature/AmazingFeature`)
3. **Committez** vos changements (`git commit -m 'Add some AmazingFeature'`)
4. **Poussez** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrez** une Pull Request

## 📋 Standards de développement

### Code Python (Backend)
- Suivez PEP 8
- Documentez les fonctions complexes
- Ajoutez des tests pour les nouvelles fonctionnalités
- Utilisez des noms de variables explicites

### Code Frontend (Next.js)
- Utilisez TypeScript
- Suivez les conventions de nommage React
- Utilisez les hooks appropriés
- Maintenez la cohérence avec Tailwind CSS

### Tests
- Testez vos changements localement avec Docker
- Vérifiez que le honeypot capture correctement les requêtes
- Testez sur différents navigateurs si nécessaire

## 🐳 Test avec Docker

```bash
# Construire et tester
./start-honeypot.sh build
./start-honeypot.sh start

# Tester les fonctionnalités
curl http://localhost:8080
curl -X POST http://localhost:8080/login -d "username=test&password=test"

# Vérifier les logs
./start-honeypot.sh logs
```

## 📝 Format des commits

Utilisez des messages de commit clairs :

```
type(scope): description

- feat: nouvelle fonctionnalité
- fix: correction de bug
- docs: documentation
- style: formatage
- refactor: refactorisation
- test: ajout de tests
- chore: tâches de maintenance
```

Exemples :
- `feat(honeypot): add IP geolocation logging`
- `fix(docker): resolve permission issues`
- `docs(readme): update deployment instructions`

## 🛡️ Sécurité

- **Ne jamais** committer de secrets ou mots de passe
- Utilisez `.env.example` pour les configurations
- Rapportez les vulnérabilités de sécurité en privé
- Testez les implications de sécurité de vos changements

## 📖 Documentation

- Mettez à jour le README si nécessaire
- Documentez les nouvelles variables d'environnement
- Ajoutez des exemples d'utilisation
- Maintenez à jour les instructions Docker

## ❓ Questions

Des questions ? N'hésitez pas à :
- Ouvrir une issue de discussion
- Contacter les mainteneurs
- Consulter la documentation existante

---

Merci de contribuer à rendre ce honeypot plus utile pour la communauté cybersécurité ! 🔒
