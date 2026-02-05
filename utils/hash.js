import bcrypt from "bcryptjs";

export const hash = async (data) => {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(data, salt);
};

export const compare = async (data, hashedData) => {
    return await bcrypt.compare(data, hashedData);
};
