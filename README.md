# php-analyzes-execute-file-format[![Latest Stable Version](https://poser.pugx.org/projectmit/php-analyzes-execute-file-format/v/stable.svg)](https://packagist.org/packages/projectmit/php-analyzes-execute-file-format)
[![Total Downloads](https://poser.pugx.org/projectmit/php-analyzes-execute-file-format/downloads.svg)](https://packagist.org/packages/projectmit/php-analyzes-execute-file-format)
[![Latest Unstable Version](https://poser.pugx.org/projectmit/php-analyzes-execute-file-format/v/unstable.svg)](https://packagist.org/packages/projectmit/php-analyzes-execute-file-format)
[![License](https://poser.pugx.org/projectmit/php-analyzes-execute-file-format/license.svg)](https://packagist.org/packages/projectmit/php-analyzes-execute-file-format)

## About
This project can analyzes for functions list of the Windows-Execute-File.
The php-analyzes-execute-file-format's project will be support of future on feature like next.

## Installation
You have multiple ways to install php-analyzes-execute-file-format.

### Composer
1. Install composer in your project : `curl -s http://getcomposer.org/installer | php`
2. Create a composer.json file or update it in your project root : 

    ```javascript
    "require": {
        "projectmit/php-analyzes-execute-file-format" : "0.1.0"
    }
    ```

    or

    ```javascript
    "require": {
        "projectmit/php-analyzes-execute-file-format" : "dev-master"
    }
    ```

3. Install via composer : `php composer.phar install`

## Licence
This software is distributed under MIT Licence.

## Support list of future
1. This library can analyzes to the PE-header in the windows-execute-file.
2. The DLL(Dynamic Link Library) list and functions list that use in the windows-execute-file is extract.
3. Analysis for the extension name
4. Get to the machine commands and assembly codes in the specific function.
5. Searching string list of the windows-execute-file.
6. The Execute File Format of Linux(ELF File Format) will be support.
