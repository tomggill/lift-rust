-- Add up migration script here
DROP TABLE IF EXISTS `sessions`;

CREATE TABLE `sessions` (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    csrf_token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
