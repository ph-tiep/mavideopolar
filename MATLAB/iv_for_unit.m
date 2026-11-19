function iv = iv_for_unit(iv_master, unit_id)
% JCM: subkey_i = AES-CTR(K, IV, counter i).
% unit_id (0 = audio, 1..T = frame) ghi vào 4 byte ĐẦU.
% Java AES-CTR tăng bộ đếm từ byte cuối -> các đơn vị không trùng keystream.
iv = iv_master;
idb = typecast(uint32(unit_id), 'int8');
iv(1:4) = idb;
end
