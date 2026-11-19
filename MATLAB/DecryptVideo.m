close all; clear; clc;

% ================= DecryptVideo.m =================
% Giải mã JCM: tái tạo subkey AES-CTR(K, IV, ctr) -> Polar decode
% -> bỏ frozen subkey -> XOR information bits. Dùng Encrypted_Data.mat.

inputDataFile   = 'Encrypted_Data.mat';
finalOutputFile = 'Final_Decrypted.avi';

if ~isfile(inputDataFile)
    error('Không tìm thấy %s. Hãy chạy EncryptVideo.m trước.', inputDataFile);
end

load(inputDataFile);

if ~exist('Enc_Frames', 'var') || ~exist('IV_List', 'var')
    error('File .mat cũ (AES-only). Hãy chạy lại EncryptVideo.m bản Polar.');
end

N = double(N); K = double(K);
[Info_Indices, ~] = polar_indices(N, K);
KEY_GLOBAL = int8([10, -20, 30, -40, 50, -60, 70, -80, 90, -100, 110, -120, 15, -25, 35, -45]);

H = frame_size(1); W = frame_size(2); C = frame_size(3);
num_pixels = H * W * C;

%% BƯỚC 1: GIẢI MÃ ÂM THANH
fprintf('1. Đang giải mã âm thanh...\n');
nAudioBytes = prod(audio_size) * 2; % int16 = 2 byte/mẫu
dec_audio_u8 = decrypt_polar_aes(enc_audio_bytes, nAudioBytes, KEY_GLOBAL, iv_audio, N, K, Info_Indices);
dec_audio_int16 = typecast(dec_audio_u8, 'int16');
audioData = reshape(double(dec_audio_int16) / 32767, audio_size);

totalAudioSamples = size(audioData, 1);
numChannels = size(audioData, 2);

%% BƯỚC 2: GIẢI MÃ TỪNG FRAME TỪ Enc_Frames
fprintf('2. Đang giải mã hình và ghép tiếng...\n');
if ~exist('frameRate', 'var') || isempty(frameRate)
    frameRate = 30;
end

useAudio = true;
try
    vWriter = vision.VideoFileWriter(finalOutputFile, ...
        'FileFormat', 'AVI', 'FrameRate', frameRate, 'AudioInputPort', true);
catch
    warning('Không có Computer Vision Toolbox. Ghi AVI không tiếng.');
    vWriter = VideoWriter(finalOutputFile);
    vWriter.FrameRate = frameRate;
    open(vWriter);
    useAudio = false;
end

chunkSize = max(1, round(Fs / frameRate));

for frameCount = 1:nFrames
    cipher_u8 = Enc_Frames{frameCount};
    iv_bytes = IV_List{frameCount};
    dec_u8 = decrypt_polar_aes(cipher_u8, num_pixels, KEY_GLOBAL, iv_bytes, N, K, Info_Indices);
    decrypted_frame = reshape(dec_u8, H, W, C);

    audioChunk = zeros(chunkSize, numChannels);
    startIdx = (frameCount - 1) * chunkSize + 1;
    endIdx = startIdx + chunkSize - 1;
    if startIdx <= totalAudioSamples
        if endIdx <= totalAudioSamples
            audioChunk(:,:) = audioData(startIdx:endIdx, :);
        else
            validLen = totalAudioSamples - startIdx + 1;
            audioChunk(1:validLen, :) = audioData(startIdx:totalAudioSamples, :);
        end
    end

    if useAudio
        step(vWriter, decrypted_frame, audioChunk);
    else
        writeVideo(vWriter, decrypted_frame);
    end

    if mod(frameCount, 10) == 0
        fprintf('  Đã giải mã %d / %d frames\n', frameCount, nFrames);
    end
end

if useAudio
    release(vWriter);
else
    close(vWriter);
end

fprintf('\nHoàn tất! Video khôi phục: %s\n', finalOutputFile);
%% ================= CÁC HÀM HỖ TRỢ (DÁN Ở CUỐI FILE) =================
function dec_u8 = decrypt_polar_aes(cipher_u8, num_target_bytes, key_bytes, iv_bytes, N, K, Info_Indices)
    import javax.crypto.*;
    import javax.crypto.spec.*;
    
    % 1. Cấu hình Ma trận sinh Polar Gn 
    % (Trong trường GF(2), ma trận Gn tự nghịch đảo: Gn * Gn = I)
    n_log = log2(N); Gn = 1; F = [1 0; 1 1];
    for i = 1:n_log, Gn = kron(Gn, F); end
    
    % 2. Chuyển byte bản mã thành chuỗi bit
    bits_raw = reshape(dec2bin(cipher_u8, 8).' - '0', 1, []);
    num_blocks = floor(length(bits_raw) / N);
    x_mat = reshape(bits_raw(1:num_blocks*N), N, []).';
    
    % 3. Khởi tạo AES-CTR để tạo lại dòng khóa Mask
    sKeySpec = javaObject('javax.crypto.spec.SecretKeySpec', key_bytes, 'AES');
    ivSpec = javaObject('javax.crypto.spec.IvParameterSpec', iv_bytes);
    aes_obj = javaMethod('getInstance', 'javax.crypto.Cipher', 'AES/CTR/NoPadding');
    
    % Mode 2 = DECRYPT_MODE (Với CTR, bản chất vẫn là sinh lại Keystream)
    aes_obj.init(2, sKeySpec, ivSpec); 
    
    plain_bits = zeros(1, num_blocks * K);
    
    % 4. Vòng lặp giải mã cho từng khối
    for i = 1:num_blocks
        % a) Giải mã Polar: Nhân vector mã hóa với Gn trong trường GF(2)
        u_full = mod(x_mat(i, :) * Gn, 2);
        
        % b) Trích xuất phần chứa dữ liệu đã bị XOR
        u_info = u_full(Info_Indices); 
        
        % c) Sinh khóa AES tương ứng
        req_bytes = ceil((N + 64)/8);
        zeros_in = zeros(1, req_bytes, 'int8');
        keystream_bytes = aes_obj.update(zeros_in); 
        bits_out = reshape(dec2bin(typecast(keystream_bytes, 'uint8'), 8).' - '0', 1, []);
        Mask = bits_out(1:K); % Chỉ lấy phần khóa dùng cho dữ liệu
        
        % d) Giải mã (XOR) để lấy bản rõ
        plain_bits((i-1)*K + 1 : i*K) = bitxor(u_info, Mask);
    end
    
    % 5. Loại bỏ padding và đóng gói lại thành mảng byte uint8
    num_target_bits = num_target_bytes * 8;
    plain_bits = plain_bits(1:num_target_bits);
    dec_u8 = uint8(bin2dec(reshape(char(plain_bits + '0'), 8, []).'));
end
