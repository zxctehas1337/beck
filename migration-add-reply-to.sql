-- Миграция для добавления поддержки ответов на сообщения
-- Добавляем поле reply_to в таблицу messages

-- Проверяем, существует ли уже поле reply_to
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'messages' AND column_name = 'reply_to'
    ) THEN
        -- Добавляем поле reply_to
        ALTER TABLE messages ADD COLUMN reply_to INTEGER;
        
        -- Добавляем внешний ключ на таблицу messages
        ALTER TABLE messages 
        ADD CONSTRAINT fk_messages_reply_to 
        FOREIGN KEY (reply_to) REFERENCES messages(id) ON DELETE SET NULL;
        
        -- Создаем индекс для оптимизации запросов по ответам
        CREATE INDEX IF NOT EXISTS idx_messages_reply_to ON messages(reply_to);
        
        RAISE NOTICE 'Field reply_to added successfully';
    ELSE
        RAISE NOTICE 'Field reply_to already exists';
    END IF;
END $$;

-- Проверяем результат
SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'messages' AND column_name = 'reply_to';
