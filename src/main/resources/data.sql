INSERT INTO users (username, password, role, failed_attempts, is_account_non_locked)
VALUES
    ('admin', 'admin_password', 'ADMIN', 0, TRUE),
    ('moderator', 'moderator_password', 'MODERATOR', 2, TRUE),
    ('user1', 'user1_password', 'USER', 0, FALSE),
    ('user2', 'user2_password', 'USER', 3, TRUE);
