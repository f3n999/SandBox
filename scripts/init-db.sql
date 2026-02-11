-- Initialisation des bases de données
-- Exécuté automatiquement au premier démarrage de PostgreSQL

CREATE DATABASE orchestrator_db;
CREATE DATABASE cape_db;

-- Utilisateur orchestrateur (mot de passe via variable d'env)
CREATE USER orchestrator_user WITH PASSWORD 'CHANGE_ME_IN_ENV';
GRANT ALL PRIVILEGES ON DATABASE orchestrator_db TO orchestrator_user;

-- Utilisateur CAPE
CREATE USER cape_user WITH PASSWORD 'CHANGE_ME_IN_ENV';
GRANT ALL PRIVILEGES ON DATABASE cape_db TO cape_user;
