SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;


CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `login` varchar(64) NOT NULL,
  `password_hash` varchar(512) NOT NULL,
  `salt` varchar(16) NOT NULL,
  `storage` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES
(1, 'test', 'f398f2a39b06e29d8e5a3973615af742f3db2a44a87a43480b0279f2df813fa7e592f03e36d7b3ebceaf5534b2bbe63892cf64b09798bd9285587a33e3dafc956bda89ee369c2e67b707480e538d798fa03dffe7f796902a791adc64a5c90b7a584685e071e66be0fb943686aeb336104033f4933c1d3d7a095675e75cc4d65a', 'bL9QKJTty4PlaNlk', 1),
(2, 'testhmac', 'bc833cd3001f14f56d8f1e6837bb4634992923e7ebb027afb113bfb51eec59c60007caaa94b1751a7d2ba50857836b2c722b5a6f959bd3a6ab5bf7fc3a75464f', '6W7CpThPU3X6UAgN', 2);

CREATE TABLE `vault` (
  `id` int(11) NOT NULL,
  `userid` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `website` varchar(64) DEFAULT NULL,
  `password` varbinary(512) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES
(1, 1, 'Testpass 1', 'google.com', 0xb963f67575dfc5da),
(2, 1, 'Testpass 2', 'bing.com', 0xbd67f67271dbc5dd),
(3, 2, 'Testpass 3', 'duck.com', 0x15dec6d25e63fdf0),
(4, 2, 'Testpass 4', 'yandex.ru', 0x11dac6d55a67fdf7);


ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

ALTER TABLE `vault`
  ADD PRIMARY KEY (`id`);


ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=32;

ALTER TABLE `vault`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
