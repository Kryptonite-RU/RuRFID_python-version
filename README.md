# RuRFID_python-version

Реализация протокола аутентификации для RFID на языке *Python*.

Содержит 1 файл реализации "**rfid_python.py**.
"**rfid_python.py**" содержит основной алгоритм взаимодействия метки (*Tag*) и устройства (*Interrogator*).

*Основные функции*:
1. "**def tag**" реализует работу метки во всех 3-х режимах. Включает в себя объявление класса "**class Tag**", описывающего основной функционал метки.
2. "**def communication**" включает в себя объявление класса "**class Interrogator**", описывающего основной функционал устройства. Реализует работу метки во всех 3-х режимах и взаимодействие между меткой и устройством (через создание дополнительного процесса-метки). 
3. "**def CONTROL_TEST_M_C**", $M \in \{ TAM, IAM, MAM\}$, $C \in \{ magma, grasshopper\}$ реализуют протокол с параметрами из контрольных примеров.

**"Transcripts_magma, Transcripts_kuznechik"** - папки с транскрипциями соответствующих режимов для метки/устройства. 

Во время работы создаётся/переписывается файл "**M_int.log**", в котором отражается вся работа устройства и создается/дописывается файл "**M_tag.log**", в котором отражается вся работа метки.

