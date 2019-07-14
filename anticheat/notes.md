One important characteristic thatcould impact the DNNs’ accuracy is the size of the training set which varies between 16 and 8926for  respectively  DiatomSizeReduction  and  ElectricDevices  datasets.  We  should  note  that  twentydatasets contains a relatively small training set (50 or fewer instances) which surprisingly was notan impediment for obtaining high accuracy when applying a very deep architecture such as ResNet.Furthermore, the number of classes varies between 2 (for 31 datasets) and 60 (for the ShapesAlldataset).

Generic for different types of games:
- shooting games -> aim pattern
- sandbox games, tetris, etc. -> movement and position
- platformers, racing games -> turning and movement patterns, velocity, acceleration

References:

# https://www.spigotmc.org/threads/machine-learning-killaura-detection-in-minecraft.301609/
Case study on KillAura detection for Minecraft. Classification using LVQ (Learning Vector Quantization) algorithm.

# https://arxiv.org/pdf/1809.04356.pdf
## Deep learning for time series classification: a review
Source code at: https://github.com/hfawaz/dl-4-tsc
Trained different types of classifiers with time-series dataset. (CNN, ResNet, t-LeNet, etc.)

- Easy to generate dataset. Use a cheat engine and instrument game code at runtime. https://github.com/jaiverma/headshot
- Reverse engineer android application. For generating timeseries dataset for a game, reverse engineer game logic and instrument via dynamic library injection or with a dynamic binary instrumentation framework such as Frida.
- Sniff network traffic with Wireshark, reverse network packets.
- Mock network traffic with instrumentation framework.
