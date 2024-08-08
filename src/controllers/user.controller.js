import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiErrors } from "../utils/ApiErrors.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiErrors(
      500,
      "Something went wrong while generating access and refresh token"
    );
  }
};
const registerUser = asyncHandler(async (req, res) => {
  //get user details from frontend
  //validation- not empty
  //check if user already exist: through username or email
  //check for images or check for avatar
  //upload them to cloudinary, or check  avatar uploaded successfully or not
  //create user object - create entry in db
  // remove password and refreshtoken field from response
  //check for user created or not
  //return response

  const { fullName, email, username, password } = req.body;
  //console.log("email: ", email);

  //validation
  if (
    [fullName, email, username, password].some((field) => field?.trim() == "")
  ) {
    throw new ApiErrors(400, "All fields are required");
  }
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (existedUser) {
    throw new ApiErrors(409, "User with username & email already existed");
  }
  //console.log(req.files);
  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;
  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiErrors(400, "Avatar file is required");
  }
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!avatar) {
    throw new ApiErrors(400, "Avatar file is required");
  }

  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  if (!createUser) {
    throw new ApiErrors(500, "Something went wrong while creating the user");
  }

  return res
    .status(201)
    .json(new ApiResponse(200, createUser, "User registered successfully"));
});
const loginUser = asyncHandler(async (req, res) => {
  //req.body---data
  //username or email
  //find user
  //password check
  //accesstoken and refresh token
  //send cookie
  const { email, username, password } = req.body;
  if (!(email || username)) {
    throw new ApiErrors(400, "username or email is required");
  }
  const user = await User.findOne({
    $or: [{ email }, { username }],
  });
  if (!user) {
    throw new ApiErrors(404, "user does not exist");
  }
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiErrors(401, "incorrect password (invalid user credentials)");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id
  );

  const logedinUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: logedinUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully"
      )
    );
});
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;
  if (!incomingRefreshToken) {
    throw new ApiErrors(401, "Unauthorized request");
  }
  try {
    const decodedToken = jwt.verify(incomingRefreshToken, REFRESH_TOKEN_SECRET);
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiErrors(401, "Invalid refresh token");
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiErrors(401, "refresh token is expired or used");
    }
    const options = {
      httpOnly: true,
      secure: true,
    };
    const { newRefreshToken, accessToken } =
      await generateAccessAndRefreshToken(user._id);
    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("newRefreshToken", options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiErrors(401, error?.message || "Invalid refresh token");
  }
});
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
  if (!(newPassword === confirmPassword)) {
    throw new ApiErrors(400, "Password mismatch");
  }
  const user = await User.findById(req.user?._id);
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) {
    throw new ApiErrors(400, "Invalid old password");
  }
  user.password = newPassword;
  await user.save({ validateBeforeSave: true });
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});
const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});
const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.user;
  if (!fullName || !email) {
    throw new ApiErrors(400, "All fields are required");
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        username,
        email: email,
      },
    },
    { new: true }
  ).select("-password");
  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"));
});
const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatartLocalPath = req.file?.path;
  if (!avatartLocalPath) {
    throw new ApiErrors(400, "Avatar file is missing");
  }
  const avatar = await uploadOnCloudinary(avatartLocalPath);
  if (!avatar.url) {
    throw new ApiErrors(400, "Error while uploading avatar on cloudinary");
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    { new: true }
  ).select("-password");
  returnres
    .status(200)
    .json(new ApiResponse(200, user, "Avatar update successfully"));
});
const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImagetLocalPath = req.file?.path;
  if (!coverImagetLocalPath) {
    throw new ApiErrors(400, "Cover image file is missing");
  }
  const coverImage = await uploadOnCloudinary(coverImagetLocalPath);
  if (!coverImage.url) {
    throw new ApiErrors(400, "Error while uploading Cover image on cloudinary");
  }
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    { new: true }
  ).select("-password");
  returnres
    .status(200)
    .json(new ApiResponse(200, user, "Cover image update successfully"));
});
const getUserChannnelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;
  if (!username?.trim()) {
    throw new ApiErrors(400, "Username is not found");
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase(),
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribed",
      },
    },
    {
      $addFields: {
        subscriberCount: {
          $size: "$subscribers",
        },
        subscribedChannelsCount: {
          $size: "$subscribed",
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
            then: true,
            else: false,
          },
        },
      },
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        subscriberCount: 1,
        subscribedChannelsCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
        createdAt: 1,
      },
    },
  ]);
  if (!channel?.length) {
    throw new ApiErrors(400, "Channel doesn't exist");
  }
  return res
    .status(200)
    .json(
      new ApiResponse(200, channel[0], "user channel fetched successfully")
    );
});
export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannnelProfile,
};
