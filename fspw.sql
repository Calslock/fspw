-- phpMyAdmin SQL Dump
-- version 5.1.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Czas generowania: 24 Paź 2021, 20:44
-- Wersja serwera: 10.4.21-MariaDB
-- Wersja PHP: 8.0.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Baza danych: `fspw`
--

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `login` varchar(64) NOT NULL,
  `password_hash` varchar(512) NOT NULL,
  `salt` varchar(16) NOT NULL,
  `storage` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Zrzut danych tabeli `users`
--

INSERT INTO `users` (`id`, `login`, `password_hash`, `salt`, `storage`) VALUES
(20, 'qwerty', 'dd9c8d838867919bf1b59dbd189cd282eb42f867ea0be6419eaab2ea2b51fedaa63a1aed7a62208304479e25dc8556a79aa76e6882430e952c07a111898fc5ef8b454f8209686557e65611f6c5fa6c6b1bff4cc1c976a8d09cbb92a1fed97b5e3d9a3fadf1f92b35f92242142b478c966bc5664ffbabdc199e6cafe2dec28506', '6YGSs9g2FRjwnaGG', 1),
(21, 'as', 'e392084236e875c013ea5ceff9c76eaf437dd3e65f503b1eca9b5cb81bdd5282c8ec38ec36a4bc5479aec1e9d9addd94b6bc6bbba312d7f821245b299631b7d6a4d624ce15f298555502474dba827181c2826964986ed9be58b8b8950102a5df0b6b62d2949e4f4ac82abe63f35d9c8802aaa7c09cdde47908ee27e1bf4f8aae', 'w31GFdq00eNaoASZ', 1),
(22, 'asasas', '83651614a5d00485725ebd53fbc77b1321106dd44182728d9916a9e672559cb4b9c133f29b5e9e9d9afff6b122dd267cc8b49906a628b70ff72f85e10e7ccec8ecdfbeb37e8a0d4642f2d413234388c33ad3415e17dfca63bcc2a81d1e9c8393d5b188c9802faf9145cc5fcd80f21e349e5228c207ae867036e8167e18dfe81c', 'clddPHA2vDYU0N3W', 1);

-- --------------------------------------------------------

--
-- Struktura tabeli dla tabeli `vault`
--

CREATE TABLE `vault` (
  `id` int(11) NOT NULL,
  `userid` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `website` varchar(64) DEFAULT NULL,
  `password` varbinary(512) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Zrzut danych tabeli `vault`
--

INSERT INTO `vault` (`id`, `userid`, `name`, `website`, `password`) VALUES
(1, 20, 'nazwa1', 'haslo1', 0x0b4c7188d493),
(2, 20, 'nazwa2', 'haslo2', 0x0b4c7188d4936f),
(3, 20, 'nazwa3', 'haslo3', 0x0b4c7188d4936e),
(4, 20, 'nazwa4', 'nazwa4', 0x0b4c7188d49369),
(5, 20, 'nazwa5', 'nazwa5', 0x0b4c7188d49368),
(6, 20, 'nazwa6', 'nazwa6', 0x0b4c7188d4936b),
(7, 20, 'haslo7', 'haslo7', 0x0b4c7188d4936a);

--
-- Indeksy dla zrzutów tabel
--

--
-- Indeksy dla tabeli `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- Indeksy dla tabeli `vault`
--
ALTER TABLE `vault`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT dla zrzuconych tabel
--

--
-- AUTO_INCREMENT dla tabeli `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- AUTO_INCREMENT dla tabeli `vault`
--
ALTER TABLE `vault`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
