-- Создание базы данных
CREATE DATABASE nitronx_db;

-- Создание пользователя
CREATE USER nitronx_user WITH PASSWORD 'nitronx_password';

-- Предоставление прав пользователю на базу данных
GRANT ALL PRIVILEGES ON DATABASE nitronx_db TO nitronx_user;

-- Подключение к базе данных nitronx_db
\c nitronx_db

-- Предоставление прав на схему public
GRANT ALL ON SCHEMA public TO nitronx_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO nitronx_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO nitronx_user;

-- Выход из psql
\q
