export const getWorkoutsService = async ({
  token,
  value,
  filterType,
  filterMuscleGroup,
}) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/workout?name=${value}&type=${filterType}&muscle=${filterMuscleGroup}`,
    {
      headers: {
        Authorization: token,
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.workouts;
};

export const registerUserService = async ({ name, email, password }) => {
  const response = await fetch(`${process.env.REACT_APP_BACKEND}/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name, email, password }),
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }
  return json.data;
};

export const loginUserService = async ({ email, password }) => {
  const response = await fetch(`${process.env.REACT_APP_BACKEND}/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  const loginInfo = {
    token: json.authToken,
    userRole: json.userInfo.role,
    userId: json.userInfo.id,
    error: json.message,
  };

  return loginInfo;
};

export const addWorkoutService = async ({
  name,
  type,
  description,
  muscle_group,
  token,
}) => {
  const response = await fetch(`${process.env.REACT_APP_BACKEND}/addWorkout`, {
    method: "POST",
    headers: {
      Authorization: token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name, type, description, muscle_group }),
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};

export const likeWorkoutService = async ({ id, token }) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/workouts/${id}/like`,
    {
      method: "PUT",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};

export const dislikeWorkoutService = async ({ id, token }) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/workouts/${id}/dislike`,
    {
      method: "DELETE",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};

export const deleteWorkoutService = async ({ id, token }) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/deleteWorkout/${id}`,
    {
      method: "DELETE",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};

export const editWorkoutService = async ({
  idWorkout,
  name,
  type,
  description,
  muscle_group,
  token,
}) => {
  console.log(name);
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/editworkouts/${idWorkout}`,
    {
      method: "PUT",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name, type, description, muscle_group }),
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.workout;
};

export const getUserFavsWorkoutService = async ({ token, idUser }) => {
  const response = await fetch(`${process.env.REACT_APP_BACKEND}/favworkouts`, {
    headers: {
      Authorization: token,
    },
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.workouts;
};

export const favWorkoutService = async ({ id, token }) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/workouts/${id}/fav`,
    {
      method: "PUT",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};

export const quitfavWorkoutService = async ({ id, token }) => {
  const response = await fetch(
    `${process.env.REACT_APP_BACKEND}/workouts/${id}/quitfav`,
    {
      method: "DELETE",
      headers: {
        Authorization: token,
        "Content-Type": "application/json",
      },
    }
  );

  const json = await response.json();

  if (!response.ok) {
    throw new Error(json.message);
  }

  return json.data;
};